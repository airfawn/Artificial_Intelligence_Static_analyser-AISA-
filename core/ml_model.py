"""
AI / ML String Classifier & Reinforcement Learning Feedback Framework.
Extracts vector features from strings (syntactic, entropy, obfuscation markers)
and provides an RL/Active-Learning training harness to continuously refine
detection against obfuscated and stealthy strings.
"""

import math
import json
import os
from typing import List, Dict, Any, Tuple


class StringFeatureExtractor:
    """Extracts normalized numerical feature vectors from raw strings for ML models."""

    @staticmethod
    def extract_features(text: str) -> Dict[str, float]:
        length = len(text)
        if length == 0:
            return {
                "norm_length": 0.0,
                "norm_entropy": 0.0,
                "digit_ratio": 0.0,
                "alpha_ratio": 0.0,
                "upper_ratio": 0.0,
                "special_ratio": 0.0,
                "hex_ratio": 0.0,
                "has_url_prefix": 0.0,
                "has_path_slash": 0.0,
                "has_exe_dll": 0.0,
                "is_base64_charset": 0.0,
                "is_sensitive_api": 0.0,
                "is_hack_cmd": 0.0,
                "is_known_good": 0.0,
                "is_susp_net": 0.0,
            }

        digits = sum(c.isdigit() for c in text)
        alphas = sum(c.isalpha() for c in text)
        uppers = sum(c.isupper() for c in text)
        hex_chars = sum(c in "0123456789abcdefABCDEF" for c in text)
        specials = sum(not c.isalnum() for c in text)

        # Entropy calculation
        entropy = 0.0
        counts: Dict[str, int] = {}
        for c in text:
            counts[c] = counts.get(c, 0) + 1
        for cnt in counts.values():
            p = cnt / length
            entropy -= p * math.log2(p)

        lower_text = text.lower()
        has_url = 1.0 if any(p in lower_text for p in ["http:", "https:", "ftp:"]) else 0.0
        has_path = 1.0 if ("\\" in text or "/" in text) else 0.0
        has_binary_ext = 1.0 if any(lower_text.endswith(ext) for ext in [".exe", ".dll", ".sys", ".ps1", ".vbs", ".bat"]) else 0.0

        # Check if strictly matching base64 character set
        b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        is_b64 = 1.0 if (length >= 16 and all(c in b64_chars for c in text) and length % 4 == 0) else 0.0

        # High-signal security keywords for domain grounding
        sensitive_api_kw = [
            "virtualalloc", "writeprocess", "createremote", "queueuser",
            "ntmap", "setthreadcontext", "isdebugger", "checkremotedebugger",
            "ntqueryinformationprocess", "minidump",
            "adjusttoken", "lookupprivilege", "setwindowshook", "getasynckey",
            "urldownloadtofile", "rtlcreateuser"
        ]
        is_sensitive_api = 1.0 if any(kw in lower_text for kw in sensitive_api_kw) else 0.0

        hack_cmd_kw = [
            "bypass", "certutil", "net user", "vssadmin", "schtasks",
            "bitsadmin", "regsvr32", "rundll32", "mshta", "powershell",
            "runonce", "run\\", "currentversion\\run"
        ]
        is_hack_cmd = 1.0 if any(kw in lower_text for kw in hack_cmd_kw) else 0.0

        known_good = [
            "microsoft.com", "google.com", "xmlsoap.org", "w3.org",
            "schemas.microsoft.com", "github.com", "apple.com"
        ]
        is_known_good = 1.0 if any(kw in lower_text for kw in known_good) else 0.0

        suspicious_net = [".xyz", ".top", ".ru", ".onion", ".cc", ":4444", ":8080", "pastebin"]
        is_susp_net = 1.0 if any(kw in lower_text for kw in suspicious_net) else 0.0

        # All features normalized between 0.0 and 1.0
        return {
            "norm_length": round(min(length / 80.0, 1.0), 4),
            "norm_entropy": round(min(entropy / 6.0, 1.0), 4),
            "digit_ratio": round(digits / length, 4),
            "alpha_ratio": round(alphas / length, 4),
            "upper_ratio": round(uppers / length, 4),
            "special_ratio": round(specials / length, 4),
            "hex_ratio": round(hex_chars / length, 4),
            "has_url_prefix": has_url,
            "has_path_slash": has_path,
            "has_exe_dll": has_binary_ext,
            "is_base64_charset": is_b64,
            "is_sensitive_api": is_sensitive_api,
            "is_hack_cmd": is_hack_cmd,
            "is_known_good": is_known_good,
            "is_susp_net": is_susp_net,
        }


class StringClassifierModel:
    """
    Lightweight, explainable linear/probabilistic classifier initialized
    with domain-expert weights for malware string classification.
    Can be dynamically fine-tuned using RL reward feedback.
    """

    def __init__(self, model_file: str = "models/string_model_weights.json"):
        self.model_file = model_file
        # Normalized domain weights for features
        self.weights = {
            "bias": -1.5,
            "norm_length": 0.2,
            "norm_entropy": 0.5,
            "digit_ratio": 0.2,
            "alpha_ratio": -0.2,
            "upper_ratio": 0.2,
            "special_ratio": 0.2,
            "hex_ratio": 0.2,
            "has_url_prefix": 1.5,
            "has_path_slash": 0.5,
            "has_exe_dll": 1.0,
            "is_base64_charset": 2.5,
            "is_sensitive_api": 3.0,
            "is_hack_cmd": 3.0,
            "is_known_good": -4.0,
            "is_susp_net": 3.0,
        }
        self._load_weights()

    def _load_weights(self):
        if os.path.exists(self.model_file):
            with open(self.model_file, "r") as f:
                loaded = json.load(f)
            if not isinstance(loaded, dict):
                raise ValueError(f"Invalid model weights in {self.model_file}: expected an object")
            for name in self.weights:
                value = loaded.get(name)
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                    raise ValueError(f"Invalid or missing model weight {name!r} in {self.model_file}")
            self.weights.update(loaded)

    def save_weights(self):
        os.makedirs(os.path.dirname(self.model_file) or ".", exist_ok=True)
        with open(self.model_file, "w") as f:
            json.dump(self.weights, f, indent=2)

    def predict_suspiciousness(self, text: str) -> Tuple[float, bool]:
        """
        Computes the probability (0.0 - 1.0) of a string being suspicious / obfuscated.
        Returns: (probability, is_suspicious)
        """
        feats = StringFeatureExtractor.extract_features(text)
        z = self.weights["bias"]
        for feat, val in feats.items():
            if feat in self.weights:
                z += self.weights[feat] * val

        # Sigmoid activation
        try:
            prob = 1.0 / (1.0 + math.exp(-max(min(z, 20.0), -20.0)))
        except OverflowError:
            prob = 1.0 if z > 0 else 0.0

        is_suspicious = prob >= 0.50
        return round(prob, 4), is_suspicious


class RLFeedbackTrainer:
    """
    Reinforcement Learning & Active Learning Feedback Loop.
    Enables iterative model tuning on obfuscated vs clean ground-truth data.
    
    Reward Structure:
    - True Positive on Obfuscated/Malicious: +1.0
    - True Negative on Benign CRT/Noise: +0.5
    - False Positive on Benign: -1.5 (Penalty for false alarms)
    - False Negative on Obfuscated: -2.0 (High penalty for missed malware strings)
    """

    def __init__(self, model: StringClassifierModel, learning_rate: float = 0.05):
        self.model = model
        self.lr = learning_rate
        self.training_log: List[Dict[str, Any]] = []

    def compute_reward(self, predicted_suspicious: bool, ground_truth_suspicious: bool) -> float:
        if predicted_suspicious and ground_truth_suspicious:
            return 1.0  # TP
        elif not predicted_suspicious and not ground_truth_suspicious:
            return 0.5  # TN
        elif predicted_suspicious and not ground_truth_suspicious:
            return -1.5  # FP
        else:
            return -2.0  # FN

    def feedback_step(self, text: str, ground_truth_suspicious: bool,
                      class_weight_malicious: float = 2.0) -> Dict[str, Any]:
        """
        Performs a policy gradient / perceptron-style weight update based on the reward.

        class_weight_malicious: Gradient scaling factor for malicious samples.
        This compensates for class imbalance — when there are fewer malicious samples than
        benign samples in the training set, the model tends to predict "benign" for everything
        because that minimises loss. Multiplying the gradient by class_weight_malicious forces
        the model to take malicious label updates more seriously.
        """
        feats = StringFeatureExtractor.extract_features(text)
        prob, predicted = self.model.predict_suspiciousness(text)
        reward = self.compute_reward(predicted, ground_truth_suspicious)

        # Gradient direction: error = (target - prob) * reward_factor
        target = 1.0 if ground_truth_suspicious else 0.0
        error = target - prob

        # Apply class weight to malicious sample gradients only
        if ground_truth_suspicious:
            error *= class_weight_malicious

        # Update weights
        for feat, val in feats.items():
            if feat in self.model.weights:
                gradient = error * val
                self.model.weights[feat] += self.lr * gradient

        # Update bias
        self.model.weights["bias"] += self.lr * error

        log_entry = {
            "text": text[:40],
            "prob_before": prob,
            "predicted": predicted,
            "ground_truth": ground_truth_suspicious,
            "reward": reward,
            "new_bias": round(self.model.weights["bias"], 4),
        }
        self.training_log.append(log_entry)
        return log_entry
