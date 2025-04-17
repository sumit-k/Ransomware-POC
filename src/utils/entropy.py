import os
import math
import numpy as np
from scipy.stats import chisquare
import sys


def shannon_entropy(data):
    # Calculate byte frequency
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    
    # Calculate entropy
    entropy = 0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    
    return entropy

def calculate_metrics(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Shannon Entropy
    entropy = shannon_entropy(data)
    
    # Chi-square
    byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    expected_counts = np.full(256, len(data) / 256)
    chi2, _ = chisquare(byte_counts, expected_counts)
    
    # Cumulative sum
    cumsum = np.cumsum(np.frombuffer(data, dtype=np.uint8))
    
    return entropy, chi2, cumsum

def process_directory(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                entropy, chi2, cumsum = calculate_metrics(file_path)
                print(f"File: {file_path}")
                print(f"Shannon Entropy: {entropy:.2f}")
                print(f"Chi-square: {chi2:.2f}")
                print(f"Cumulative Sum (first 10 values): {cumsum[:10]}")
                print("---")
            except Exception as e:
                print(f"Error processing {file_path}: {str(e)}")
                print("---")

# Usage
directory_path = sys.argv[1]
process_directory(directory_path)
