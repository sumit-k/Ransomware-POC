#!/usr/bin/env python3

import argparse
import ctypes as ct
import math
import os
import sys
import time
import csv
from collections import Counter, deque, namedtuple
from statistics import mean, variance
from datetime import datetime
from dotenv import load_dotenv
from random import randrange


# --- Try importing bcc ---
try:
    from bcc import BPF
except ImportError:
    print("Error: Cannot import bcc. Make sure bcc (python3-bpfcc) is installed.", file=sys.stderr)
    sys.exit(1)

# --- Try importing boto3 ---
try:
    import boto3
    from botocore.exceptions import NoCredentialsError, ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

# --- Configuration ---
WINDOW_DURATION_SEC = 2.0
# Size of the buffer sample to read for entropy calculation (bytes)
# Larger values give more accurate entropy but increase overhead.
BUFFER_SAMPLE_SIZE = 64 # Keep this reasonably small (e.g., 64, 128, 256)

# --- Define eBPF C Code ---
# Use placeholders for dynamic values (device filtering, sample size)
bpf_text_template = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/pid_namespace.h> // For task_active_pid_ns

// Define flags if not present in headers (may vary by kernel version)
#ifndef REQ_OP_WRITE
#define REQ_OP_WRITE 1 // Assume common value if not defined
#endif
#ifndef REQ_OP_READ
#define REQ_OP_READ 0 // Assume common value if not defined
#endif

#define FILTER_DEV_TEMP 1

// Data structure to pass to user space
struct data_t {
    u64 ts_ns;          // Timestamp (nanoseconds)
    u32 pid;            // Process ID
    u32 dev_major;      // Device major number
    u32 dev_minor;      // Device minor number
    u64 lba;            // Logical Block Address (sector)
    u64 size;           // Size in bytes
    u32 is_write;       // 1 for write, 0 for read
    char comm[TASK_COMM_LEN]; // Process name
    // Add buffer sample field ONLY if compiling for write entropy
    // We use conditional compilation based on a define passed from Python
#ifdef CAPTURE_WRITE_BUFFER
    unsigned char buf_sample[__SAMPLE_SIZE__]; // Buffer sample for writes
#endif
};

static __always_inline  int is_write_op(const char *cs, unsigned char op, int size)
{
    int len = 0;
    unsigned char c1;
    for (len=0;len< (size & 0xff);len++) {
        c1 = *(cs + len);
        if (c1 == op) return 1;
     }
     return 0;
}


// Perf buffer to send data to user space
BPF_PERF_OUTPUT(events);

// Use tracepoint for block request completion
// Arguments for block_rq_complete: struct request *rq, int error, unsigned int nr_bytes
TRACEPOINT_PROBE(block, block_rq_complete) {
    unsigned int nr_bytes = args->nr_sector << 9;

    u32 major = MAJOR(args->dev);
    u32 minor = MINOR(args->dev);
//#ifdef FILTER_DEV
    if (major != __TARGET_DEV_MAJOR__ || minor != __TARGET_DEV_MINOR__) {
        return 0; // Not the target device
    }
//#endif

    // Basic request info
    u64 sector = (unsigned long long)(args->sector);
    u64 completed_size = nr_bytes; // Actual completed size

    // If completed size is 0, might be error or metadata op, skip for stats
    if (completed_size == 0) {
        return 0;
    }

    // --- Prepare data structure ---
    struct data_t data = {};
    data.ts_ns = bpf_ktime_get_ns();
    data.lba = sector;
    data.size = completed_size;
    data.dev_major = major;
    data.dev_minor = minor;

    // Get PID and command
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.is_write = is_write_op(args->rwbs, 'W', 8);

    // Submit data to user space
    events.perf_submit(args, &data, sizeof(data));

    return 0;
}
"""

# --- Python Data Structure (must match C struct) ---
class Data(ct.Structure):
    _fields_ = [
        ("ts_ns", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("dev_major", ct.c_uint),
        ("dev_minor", ct.c_uint),
        ("lba", ct.c_ulonglong),
        ("size", ct.c_ulonglong),
        ("is_write", ct.c_uint),
        ("comm", ct.c_char * 16), # TASK_COMM_LEN=16
        ("buf_sample", ct.c_ubyte * BUFFER_SAMPLE_SIZE), # Match sample size
    ]

# --- Data structure for holding processed trace events ---
TraceEvent = namedtuple("TraceEvent", ["timestamp_s", "op_type", "lba", "size", "entropy"])

# --- Shannon Entropy Calculation ---
def calculate_shannon_entropy(byte_array):
    # ... (same implementation) ...
    byte_counts = Counter(byte_array)
    total_bytes = len(byte_array)
    entropy = 0.0
    if total_bytes == 0: return 0.0
    for count in byte_counts.values():
        probability = count / total_bytes
        if probability > 0: entropy -= probability * math.log2(probability)
    return entropy

# --- Metrics Calculation ---
def calculate_metrics(events_in_window, window_duration):
    """Calculates metrics for the events within the current window."""
    read_events = [e for e in events_in_window if e.op_type == 'R']
    write_events = [e for e in events_in_window if e.op_type == 'W']

    read_count = len(read_events)
    write_count = len(write_events)
    total_read_bytes = sum(e.size for e in read_events)
    total_write_bytes = sum(e.size for e in write_events)
    avg_read_speed_bps = total_read_bytes / window_duration if window_duration > 0 else 0
    avg_write_speed_bps = total_write_bytes / window_duration if window_duration > 0 else 0
    read_lbas = [e.lba for e in read_events]
    write_lbas = [e.lba for e in write_events]

    read_lba_variance = variance(read_lbas) if len(read_lbas) >= 2 else 0.0
    write_lba_variance = variance(write_lbas) if len(write_lbas) >= 2 else 0.0
    # Entropy calculations (only for writes)
    write_entropies = [e.entropy for e in write_events if e.entropy is not None]
    min_write_entropy = min(write_entropies) if write_entropies else 0.0
    max_write_entropy = max(write_entropies) if write_entropies else 0.0
    avg_write_entropy = mean(write_entropies) if write_entropies else 0.0

    return {
        "read_count": read_count,
        "write_count": write_count,
        "avg_read_speed_bps": avg_read_speed_bps,
        "avg_write_speed_bps": avg_write_speed_bps,
        "read_lba_variance": read_lba_variance,
        "write_lba_variance": write_lba_variance,
        "min_write_entropy": min_write_entropy,
        "max_write_entropy": max_write_entropy,
        "avg_write_entropy": avg_write_entropy,
        "window_event_count": len(events_in_window),
        "write_entropy_count": len(write_entropies),
    }


# --- Global Deque for Events (accessed by callback) ---
# Consider thread safety if callback were truly concurrent, but perf_buffer_poll is usually single-threaded
events_deque = deque()
last_print_time_ns = 0
csv_writer = None
csv_fieldnames = [
    'timestamp_s', 'window_duration_s', 'device_major', 'device_minor',
    'read_count', 'write_count', 'avg_read_speed_mbps', 'avg_write_speed_mbps',
    'read_lba_variance', 'write_lba_variance', 'min_write_entropy',
    'max_write_entropy', 'avg_write_entropy', 'write_entropy_count',
    'total_event_count', 'label'
]

# --- Process Events Callback (Unchanged CSV writing logic) ---
def process_event(cpu, data, size):
    """Callback function to process data received from eBPF perf buffer."""
    global events_deque, last_print_time_ns, csv_writer

    event = ct.cast(data, ct.POINTER(Data)).contents
    timestamp_s = event.ts_ns / 1e9 # Convert ns to seconds
    op_type = 'W' if event.is_write else 'R'
    entropy = None
    if op_type == 'W':
        # Convert c_ubyte array to bytes/bytearray for entropy calculation
        buffer_sample_bytes = bytes(event.buf_sample)
        # Only calculate entropy if the sample likely contains data
        # (Check size or if it's non-zero, though eBPF code tries to zero on error)
        if event.size > 0: # Assuming sample is relevant if op completed with size > 0
            entropy = calculate_shannon_entropy(buffer_sample_bytes)
        else:
            entropy = 0.0 # Assign 0 if write size was 0



    # Create TraceEvent
    processed_event = TraceEvent(
        timestamp_s=timestamp_s,
        op_type=op_type,
        lba=event.lba,
        size=event.size,
        entropy=entropy # Will be None for reads
    )

    # Append to deque
    events_deque.append(processed_event)

    # --- Sliding Window Logic ---
    current_time_s = timestamp_s # Use event time for window boundary
    window_start_time_s = current_time_s - WINDOW_DURATION_SEC
    while events_deque and events_deque[0].timestamp_s < window_start_time_s:
        events_deque.popleft()

    # --- Trigger Metric Calculation & Printing Periodically (approx 1 sec) ---
    # Use event timestamp for periodicity control relative to data flow
    if event.ts_ns - last_print_time_ns >= 1000000000: # 1 second in ns
        length = len(events_deque);
        if length:
        #if events_deque:
            metrics = calculate_metrics(events_deque, WINDOW_DURATION_SEC)
            latest_event_time_s = events_deque[-1].timestamp_s
            oldest_event_time_s = events_deque[0].timestamp_s
            actual_span_s = latest_event_time_s - oldest_event_time_s

            row_data = {
                'timestamp_s': f"{latest_event_time_s:.3f}",
                'window_duration_s': f"{WINDOW_DURATION_SEC:.1f}",
                'device_major': event.dev_major, 'device_minor': event.dev_minor,
                'read_count': metrics['read_count'], 'write_count': metrics['write_count'],
                'avg_read_speed_mbps': f"{metrics['avg_read_speed_bps']/1024/1024:.2f}",
                'avg_write_speed_mbps': f"{metrics['avg_write_speed_bps']/1024/1024:.2f}",
                'read_lba_variance': f"{metrics['read_lba_variance']:.2e}",
                'write_lba_variance': f"{metrics['write_lba_variance']:.2e}",
                'min_write_entropy': f"{metrics['min_write_entropy']:.3f}",
                'max_write_entropy': f"{metrics['max_write_entropy']:.3f}",
                'avg_write_entropy': f"{metrics['avg_write_entropy']:.3f}",
                'write_entropy_count': metrics['write_entropy_count'],
                'total_event_count': metrics['window_event_count'],
                'label': randrange(2)
            }

            if csv_writer:
                try: 
                    csv_writer.writerow(row_data)
                except Exception as e: print(f"\nError writing to CSV: {e}", file=sys.stderr)

            # Console printing remains the same
            print("-" * 70)
            print(f"Window ending ~ {latest_event_time_s:.3f}s (Span: {actual_span_s:.3f}s, Events: {metrics['window_event_count']})")
            # ... rest of console print statements ...
            print(f"  Device: {event.dev_major}:{event.dev_minor} | PID: {event.pid:<6} | Comm: {event.comm.decode('utf-8', 'replace'):<10}")
            print(f"  Read Count : {metrics['read_count']:>6d} | Write Count : {metrics['write_count']:>6d}")
            print(f"  Read Speed : {metrics['avg_read_speed_bps']/1024/1024:>8.2f} MB/s | Write Speed : {metrics['avg_write_speed_bps']/1024/1024:>8.2f} MB/s")
            print(f"  Read LBA Var: {metrics['read_lba_variance']:>12.2e} | Write LBA Var: {metrics['write_lba_variance']:>12.2e}")
            print(f"  Write Entropy (n={metrics['write_entropy_count']}): Min={metrics['min_write_entropy']:.3f} | Max={metrics['max_write_entropy']:.3f} | Avg={metrics['avg_write_entropy']:.3f}")
            last_print_time_ns = event.ts_ns # Update last print time based on event timestamp
        else:
             # Print zeros if window is empty but time has passed
             print("-" * 70)
             print(f"Window ending ~ {current_time_s:.3f}s (Span: 0.000s, Events: 0)")
             print(f"  (No events in window)")
             last_print_time_ns = event.ts_ns


# --- Function to Upload to IBM COS ---
def upload_to_ibm_cos(local_filepath, bucket_name, object_key, endpoint_url, access_key, secret_key):
    """Uploads a local file to IBM Cloud Object Storage."""
    if not BOTO3_AVAILABLE:
        print("\nError: 'boto3' library not found. Cannot upload to IBM COS.")
        print("Install it using: pip install boto3")
        return False

    print(f"\nAttempting upload to IBM COS:")
    print(f"  Endpoint: {endpoint_url}")
    print(f"  Bucket: {bucket_name}")
    print(f"  Object Key: {object_key}")
    print(f"  Local File: {local_filepath}")

    try:
        # Create S3 client configured for IBM COS
        s3_client = boto3.client('s3',
                                 endpoint_url=endpoint_url,
                                 aws_access_key_id=access_key,
                                 aws_secret_access_key=secret_key)

        # Upload the file
        print("  Uploading...")
        s3_client.upload_file(local_filepath, bucket_name, object_key)
        print("  Upload successful!")
        return True

    except NoCredentialsError:
        print("Error: Credentials not found by boto3.")
        print("Ensure IBM_COS_ACCESS_KEY_ID and IBM_COS_SECRET_ACCESS_KEY are set or passed correctly.")
        return False
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        print(f"Error uploading file: {e}")
        if error_code == 'NoSuchBucket':
             print(f"  -> The bucket '{bucket_name}' does not exist or you lack permissions.")
        elif error_code == 'InvalidAccessKeyId':
             print("  -> The Access Key ID provided is invalid.")
        elif error_code == 'SignatureDoesNotMatch':
             print("  -> The Secret Access Key provided is invalid.")
        elif 'ExpiredToken' in str(e):
             print("  -> Credentials may have expired.")
        else:
             print(f"  -> Check endpoint URL ('{endpoint_url}') and network connectivity.")
        return False
    except Exception as e:
        print(f"An unexpected error occurred during upload: {e}")
        return False


# --- Main Execution (Modified for Upload Option) ---
def main(args):
    global last_print_time_ns, csv_writer

    # --- Check dependencies ---
    try:
        from bcc import BPF # Check again inside main if needed
    except ImportError:
        print("Error: Cannot import bcc. Make sure bcc (python3-bpfcc) is installed.", file=sys.stderr)
        print("See https://github.com/iovisor/bcc/blob/master/INSTALL.md", file=sys.stderr)
        sys.exit(1)

    target_major = -1
    target_minor = -1
    filter_device = False
    bpf_text = bpf_text_template # Start with the base template

    # --- Prepare BPF Code (Device Filtering & Sample Size) ---
    if args.device:
        try:
            device_stat = os.stat(args.device)
            #if not os.path.isblk(device_stat.st_mode):
            #    raise ValueError("Not a block device")
            target_major = os.major(device_stat.st_rdev)
            target_minor = os.minor(device_stat.st_rdev)
            filter_device = True
            print(f"Filtering for device: {args.device} (Major: {target_major}, Minor: {target_minor})")
            # Inject device filter into BPF code
            bpf_text = bpf_text.replace("#ifdef FILTER_DEV_TEMP 1", "#define FILTER_DEV 1")
            bpf_text = bpf_text.replace("__TARGET_DEV_MAJOR__", str(target_major))
            bpf_text = bpf_text.replace("__TARGET_DEV_MINOR__", str(target_minor))
        except Exception as e:
            print(f"Warning: Cannot filter for device '{args.device}' ({e}). Monitoring ALL devices.", file=sys.stderr)
            filter_device = False
    else:
        print("No device specified, monitoring ALL block devices.")
    #if not filter_device: bpf_text = bpf_text.replace("#ifdef FILTER_DEV", "#if 0")
    #bpf_text = bpf_text.replace("#ifdef CAPTURE_WRITE_BUFFER", "#define CAPTURE_WRITE_BUFFER 1")
    bpf_text = bpf_text.replace("__SAMPLE_SIZE__", str(BUFFER_SAMPLE_SIZE))

    # Initialize BPF
    last_print_time_ns = 0
    try:
        b = BPF(text=bpf_text)
        print("eBPF program loaded successfully.")
        print(f"Sliding window: {WINDOW_DURATION_SEC}s")
        print(f"Write buffer sample size: {BUFFER_SAMPLE_SIZE} bytes")
        print("Press Ctrl+C to stop.")
    except Exception as e:
        print(f"Error loading BPF program: {e}", file=sys.stderr)
        print("Ensure kernel headers are installed and match your kernel version.", file=sys.stderr)
        print("Try running with 'sudo'.", file=sys.stderr)
        # Optionally print the generated C code for debugging
        # print("\n--- Generated BPF Code ---")
        # print(bpf_text)
        # print("------------------------\n")
        sys.exit(1)



    # Setup Perf Buffer
    b["events"].open_perf_buffer(process_event)
    #last_print_time_ns = time.time_ns()

    local_csv_filepath = args.outfile # Use the outfile path for local saving

    # Main Loop with CSV File Handling and Upload Logic
    print(f"Writing metrics to local CSV file: {local_csv_filepath}")
    #if args.upload_to_ibm_cos: 
    #    print("Upload to IBM COS enabled.")
    print("Press Ctrl+C to stop.")
    try:
        with open(local_csv_filepath, 'w', newline='') as csvfile:
            global csv_writer
            csv_writer = csv.DictWriter(csvfile, fieldnames=csv_fieldnames)
            csv_writer.writeheader()

            while True:
                try: 
                    b.perf_buffer_poll(timeout=100)
                except ValueError: 
                    break # Handle shutdown poll error
                except Exception as poll_e: 
                    print(f"Poll Error: {poll_e}", file=sys.stderr); time.sleep(1)

                # Idle stats printing (optional)
                # ... (same as before) ...

    except FileNotFoundError: print(f"Error: Could not open CSV file: {local_csv_filepath}", file=sys.stderr)
    except IOError as e: print(f"Error writing to CSV '{local_csv_filepath}': {e}", file=sys.stderr)
    except KeyboardInterrupt: print("\nStopping...")
    except Exception as e: print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)
    finally:
        print("\nDetaching eBPF program and closing resources...")
        # BPF resources cleaned up by 'b' destructor
        # CSV file closed by 'with open'

        # --- Attempt Upload if Flag is Set ---
        #if args.upload_to_ibm_cos:
        if 0:
            if not BOTO3_AVAILABLE:
                 print("\nUpload skipped: 'boto3' library is not installed.")
            elif os.path.exists(local_csv_filepath):
                 # --- Get COS Configuration ---
                 # Prefer command line args if provided, otherwise fallback to env vars
                 #endpoint = args.ibm_cos_endpoint_url or os.environ.get('IBM_COS_ENDPOINT_URL')
                 load_dotenv("/home/sumit/code/export")

                 endpoint = os.environ.get('IBM_COS_ENDPOINT_URL')
                 print("Endpoint:", endpoint)
                 bucket = args.ibm_cos_bucket_name or os.environ.get('IBM_COS_BUCKET_NAME')
                 print("Bucket name:", bucket)
                 access_key = args.ibm_cos_access_key or os.environ.get('IBM_COS_ACCESS_KEY_ID')
                 print("Access key:", access_key)
                 secret_key = args.ibm_cos_secret_key or os.environ.get('IBM_COS_SECRET_ACCESS_KEY') # Only get from arg if provided (less secure)
                 if not secret_key: # Fallback to env var if not passed via arg
                      secret_key = os.environ.get('IBM_COS_SECRET_ACCESS_KEY')

                 print("secret key:", secret_key)
                 # Check if all required config is present
                 if not all([endpoint, bucket, access_key, secret_key]):
                      print("\nUpload skipped: Missing IBM COS configuration.")
                      print("Ensure endpoint, bucket, access key, and secret key are provided via args or environment variables:")
                      print("  Args: --ibm-cos-endpoint-url, --ibm-cos-bucket-name, --ibm-cos-access-key, --ibm-cos-secret-key")
                      print("  Env Vars: IBM_COS_ENDPOINT_URL, IBM_COS_BUCKET_NAME, IBM_COS_ACCESS_KEY_ID, IBM_COS_SECRET_ACCESS_KEY")
                 else:
                      # Determine object key (use the local filename by default)
                      object_key = os.path.basename(local_csv_filepath)
                      # Add a prefix if desired, e.g., object_key = f"ebpf-metrics/{object_key}"

                      # Call the upload function
                      upload_to_ibm_cos(local_csv_filepath, bucket, object_key, endpoint, access_key, secret_key)
            else:
                 print(f"\nUpload skipped: Local file '{local_csv_filepath}' not found.")
        else:
             print(f"\nLocal metrics saved to {local_csv_filepath}. Upload skipped (flag not set).")


if __name__ == "__main__":
    # Get current time for default filename
    # Taking current date into consideration for the filename.
    now_dt = datetime.now() # Use datetime for better control
    default_outfile = f"block_metrics_{now_dt.strftime('%Y%m%d_%H%M%S')}.csv"

    # Use datetime import
    from datetime import datetime

    parser = argparse.ArgumentParser(
        description="Monitor block I/O with eBPF, log metrics to CSV, and optionally upload to IBM COS.",
        epilog="Requires 'bcc', 'boto3', kernel headers, and root privileges. "
               "Set IBM_COS_* environment variables for upload credentials (recommended)."
    )
    # --- Monitoring Args ---
    parser.add_argument("device", nargs='?', default=None,
                        help="Optional: Block device to monitor (e.g., /dev/sda). Monitors ALL if omitted.")
    parser.add_argument("-o", "--outfile", default=default_outfile,
                        help=f"Local output CSV file path (default: {default_outfile})")

    # --- IBM COS Upload Args ---
    upload_group = parser.add_argument_group('IBM Cloud Object Storage Upload Options')
    upload_group.add_argument("--upload-to-ibm-cos", action="store_true", default=False,
                              help="Enable upload of the final CSV file to IBM COS.")
    upload_group.add_argument("--ibm-cos-endpoint-url", default=None,
                              help="IBM COS endpoint URL (overrides IBM_COS_ENDPOINT_URL env var). "
                                   "Find this in your IBM Cloud COS dashboard for your bucket's region.")
    upload_group.add_argument("--ibm-cos-bucket-name", default=None,
                              help="IBM COS bucket name (overrides IBM_COS_BUCKET_NAME env var).")
    upload_group.add_argument("--ibm-cos-access-key", default=None,
                              help="IBM COS Access Key ID (overrides IBM_COS_ACCESS_KEY_ID env var).")
    upload_group.add_argument("--ibm-cos-secret-key", default=None,
                              help="IBM COS Secret Access Key (overrides IBM_COS_SECRET_ACCESS_KEY env var - use with caution).")

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: This script requires root privileges (sudo) to run eBPF programs.", file=sys.stderr)
        sys.exit(1)

    # Add a warning if keys are passed via command line
    if args.ibm_cos_secret_key:
        print("Warning: Providing Secret Key via command-line argument is less secure.", file=sys.stderr)
        print("Consider using environment variables (IBM_COS_SECRET_ACCESS_KEY) instead.", file=sys.stderr)

    main(args)
