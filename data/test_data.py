"""
Step 4: Test & Evaluation Script for String Classifier
Tests the model on unseen strings that were NOT part of training.
Run with:
    python data/test_data.py
"""

import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.ml_model import StringClassifierModel

def run_evaluation():
    model = StringClassifierModel(model_file="models/string_model_weights.json")

    # Obfuscated & edge test cases
    test_cases = [
        "aGVsbG8gd29ybGQ=",              # base64("hello world") — benign text
        "WuB3AlExbRk9G2mP8nQzX6jLkDsT",    # random high entropy — obfuscated?
        "http://update.microsoft.com",      # benign Microsoft URL
        "http://malicious-c2.ru:4444/drop", # malicious C2 URL with suspicious port
        "VirtualAllocEx",                   # critical injection API
        "NtMapViewOfSection",               # hollowing injection API
        "GetWindowsDirectoryA",             # benign Windows API
        "cmd.exe /c powershell -w hidden",  # shell command launcher
    ]

    print("\n" + "=" * 65)
    print("  Evaluating Model on Unseen Strings")
    print("=" * 65)
    for s in test_cases:
        prob, is_suspicious = model.predict_suspiciousness(s)
        label = "⚠️  SUSPICIOUS" if is_suspicious else "✅ Benign    "
        print(f"[{label}] (p={prob:.3f}) | {s}")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    run_evaluation()
