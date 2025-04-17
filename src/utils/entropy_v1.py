#!/usr/bin/env python3

import os
import math
import collections
import argparse
import sys
from scipy import stats # For chi-square

# Optional imports (check for availability)
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    print("Warning: 'python-magic' library not found. File type detection disabled.", file=sys.stderr)
    print("Install with 'pip install python-magic' and ensure libmagic system dependency is met.", file=sys.stderr)

try:
    import zlib
    ZLIB_AVAILABLE = True
except ImportError:
    # Should always be available, but check just in case
    ZLIB_AVAILABLE = False
    print("Warning: 'zlib' library not found. Compression check disabled.", file=sys.stderr)


# --- Calculation Functions ---

def calculate_shannon_entropy(byte_counts, total_bytes):
    """Calculates Shannon entropy for the given byte counts."""
    entropy = 0.0
    if total_bytes == 0:
        return 0.0
    for count in byte_counts.values():
        if count > 0:
            probability = count / total_bytes
            entropy -= probability * math.log2(probability)
    return entropy

def calculate_chi_square(byte_counts, total_bytes):
    """Calculates the Chi-square statistic against a uniform distribution."""
    if total_bytes == 0 or total_bytes < 5 * 256 : # Chi-square needs sufficient counts
         print(f"Warning: File size ({total_bytes} bytes) too small for reliable Chi-square test.", file=sys.stderr)
         return None, None # Return None if too small

    observed_freq = [byte_counts.get(i, 0) for i in range(256)]

    # Expected frequency for uniform distribution
    # Using observed total ensures sum(expected) == sum(observed)
    expected_freq = [total_bytes / 256.0] * 256

    # Perform Chi-square test
    try:
        # ddof=0 because we are comparing to a *fixed* theoretical distribution (uniform)
        chisq_stat, p_value = stats.chisquare(f_obs=observed_freq, f_exp=expected_freq, ddof=0)
        return chisq_stat, p_value
    except ValueError as e:
        # Can happen if expected frequency is zero somewhere, shouldn't happen here
        print(f"Error during Chi-square calculation: {e}", file=sys.stderr)
        return None, None


def calculate_cusum_excursion(file_path, chunk_size=65536):
    """
    Calculates the maximum absolute excursion of the cumulative sum
    of (byte_value - 127.5). Less standard than entropy/chi-square
    for encryption detection, but might show deviation from randomness.
    """
    cusum = 0.0
    max_excursion = 0.0
    min_excursion = 0.0
    total_bytes = 0
    mean_byte = 127.5 # Midpoint of 0-255 range

    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                total_bytes += len(chunk)
                for byte_val in chunk:
                    cusum += (byte_val - mean_byte)
                    max_excursion = max(max_excursion, cusum)
                    min_excursion = min(min_excursion, cusum)
        if total_bytes == 0:
             return 0.0
        # Return the maximum absolute deviation from zero
        return max(max_excursion, abs(min_excursion))
    except Exception as e:
        print(f"Error calculating CUSUM for {file_path}: {e}", file=sys.stderr)
        return None


def get_file_type(file_path):
    """Gets file type using python-magic."""
    if not MAGIC_AVAILABLE:
        return "N/A (python-magic not installed)"
    try:
        mime_type = magic.from_file(file_path, mime=True)
        description = magic.from_file(file_path)
        return f"{mime_type} | {description}"
    except magic.MagicException as e:
         # Handle errors like permission denied, file not found during magic check
         # These might differ from the main loop's open() errors
         if "cannot open" in str(e).lower() or "no such file" in str(e).lower():
             # This specific file might be gone or unreadable just for magic
             return f"Error checking type: {e}"
         # Otherwise, might be an issue with libmagic itself
         print(f"Warning: python-magic error for {file_path}: {e}", file=sys.stderr)
         return "Error" # General error
    except Exception as e:
        print(f"Unexpected error getting file type for {file_path}: {e}", file=sys.stderr)
        return "Error"


def get_compression_ratio(file_path, level=9):
    """Calculates compression ratio using zlib."""
    if not ZLIB_AVAILABLE:
        return None
    try:
        with open(file_path, "rb") as f:
            original_data = f.read()
        original_size = len(original_data)
        if original_size == 0:
            return 1.0 # Or None? Let's return 1.0 for empty files

        compressed_data = zlib.compress(original_data, level=level)
        compressed_size = len(compressed_data)
        return compressed_size / original_size
    except MemoryError:
         print(f"MemoryError: File {file_path} is too large to read for compression check.", file=sys.stderr)
         return None # Indicate failure due to size
    except Exception as e:
        print(f"Error calculating compression ratio for {file_path}: {e}", file=sys.stderr)
        return None


# --- Main Analysis Function ---
def analyze_directory(dir_path, chunk_size=65536, do_magic=True, do_compress=True):
    """Iterates through files and performs analyses."""
    print(f"Analyzing directory: {dir_path}")
    print("-" * 80)
    print(f"{'Filename':<40} {'Size (B)':>10} {'Entropy':>8} {'Chi2 Stat':>12} {'Chi2 PVal':>10} {'CUSUM Max':>12} {'Comp Ratio':>12} {'File Type'}")
    print("-" * 80)

    for root, _, files in os.walk(dir_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            try:
                byte_counts = collections.Counter()
                total_bytes = 0

                # --- Pass 1: Calculate Entropy, Chi-Square pre-reqs, CUSUM ---
                cusum = 0.0
                max_excursion = 0.0
                min_excursion = 0.0
                mean_byte = 127.5

                with open(file_path, "rb") as f:
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        current_chunk_len = len(chunk)
                        total_bytes += current_chunk_len
                        byte_counts.update(chunk)
                        # Update CUSUM within the same read pass
                        for byte_val in chunk:
                             cusum += (byte_val - mean_byte)
                             max_excursion = max(max_excursion, cusum)
                             min_excursion = min(min_excursion, cusum)

                # --- Calculate Metrics ---
                if total_bytes > 0:
                    entropy = calculate_shannon_entropy(byte_counts, total_bytes)
                    chisq_stat, p_value = calculate_chi_square(byte_counts, total_bytes)
                    cusum_max_abs_excursion = max(max_excursion, abs(min_excursion))

                    # Format results
                    entropy_str = f"{entropy:.4f}"
                    chisq_str = f"{chisq_stat:.2f}" if chisq_stat is not None else "N/A"
                    pval_str = f"{p_value:.3e}" if p_value is not None else "N/A"
                    cusum_str = f"{cusum_max_abs_excursion:.2f}"

                else: # Empty file
                    entropy_str = "0.0000"
                    chisq_str = "N/A"
                    pval_str = "N/A"
                    cusum_str = "0.00"

                # --- Optional Checks (require reading file again or separate handling) ---
                file_type_str = get_file_type(file_path) if do_magic else "Skipped"
                comp_ratio = get_compression_ratio(file_path) if do_compress else None
                comp_ratio_str = f"{comp_ratio:.4f}" if comp_ratio is not None else "Skipped/Err"

                # --- Print Results for File ---
                print(f"{file_path:<40} {total_bytes:>10} {entropy_str:>8} {chisq_str:>12} {pval_str:>10} {cusum_str:>12} {comp_ratio_str:>12} {file_type_str}")

            except FileNotFoundError:
                print(f"Warning: File not found during processing (might have been deleted): {file_path}", file=sys.stderr)
            except PermissionError:
                print(f"Warning: Permission denied for file: {file_path}", file=sys.stderr)
            except OSError as e:
                 print(f"Warning: OS Error processing file {file_path}: {e}", file=sys.stderr)
            except Exception as e:
                print(f"ERROR: Unexpected error processing file {file_path}: {e}", file=sys.stderr)
                # Optionally re-raise if you want the script to stop on unexpected errors
                # raise e

    print("-" * 80)
    print("Analysis finished.")

# --- Argument Parser and Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Analyze files in a directory for potential signs of encryption using "
                    "Shannon entropy, Chi-square test, CUSUM excursion, file type check, and compression ratio.",
        epilog="High entropy (~8.0), low Chi-square statistic (high p-value > ~0.05), "
               "low compression ratio (~1.0), and mismatched/generic file type can indicate encryption. "
               "Establish baselines on known good files."
    )
    parser.add_argument("directory", help="The directory path to analyze.")
    parser.add_argument("-c", "--chunk-size", type=int, default=65536,
                        help="Chunk size in bytes for reading large files (default: 65536).")
    parser.add_argument("--skip-magic", action="store_true",
                        help="Skip file type identification using 'python-magic'.")
    parser.add_argument("--skip-compress", action="store_true",
                        help="Skip compression ratio calculation using 'zlib'.")

    # Add more arguments if needed (e.g., output file)

    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"Error: Directory not found or not accessible: {args.directory}", file=sys.stderr)
        sys.exit(1)

    analyze_directory(
        args.directory,
        chunk_size=args.chunk_size,
        do_magic=not args.skip_magic,
        do_compress=not args.skip_compress
    )
