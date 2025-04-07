#!/usr/bin/env python3

import subprocess
import sys
import time
import argparse
from collections import deque, namedtuple
from statistics import mean, variance
import select
import os

# --- Configuration ---
WINDOW_DURATION_SEC = 10.0
# blktrace format: Timestamp Action RWBS LBA Size ProcessName
# %T.%t: Seconds.microseconds
# %a: Action (Q=queued, C=completed, etc.)
# %n: RWBS field (contains R for read, W for write)
# %N: LBA (sector number)
# %S: Size in bytes
# %p: Process Name (optional, but useful context)
BLKTRACE_FORMAT = "%T.%t %a %n %N %S %p\\n"

# Data structure for holding trace events
TraceEvent = namedtuple("TraceEvent", ["timestamp", "op_type", "lba", "size"])

def calculate_metrics(events_in_window, window_duration):
    """Calculates metrics for the events within the current window."""
    read_events = [e for e in events_in_window if e.op_type == 'R']
    write_events = [e for e in events_in_window if e.op_type == 'W']

    read_count = len(read_events)
    write_count = len(write_events)

    total_read_bytes = sum(e.size for e in read_events)
    total_write_bytes = sum(e.size for e in write_events)

    # Calculate average speed over the *fixed* window duration
    avg_read_speed_bps = total_read_bytes / window_duration if window_duration > 0 else 0
    avg_write_speed_bps = total_write_bytes / window_duration if window_duration > 0 else 0

    read_lbas = [e.lba for e in read_events]
    write_lbas = [e.lba for e in write_events]

    # Calculate LBA variance (Sample Variance)
    # Variance requires at least two data points
    read_lba_variance = variance(read_lbas) if len(read_lbas) >= 2 else 0.0
    write_lba_variance = variance(write_lbas) if len(write_lbas) >= 2 else 0.0

    return {
        "read_count": read_count,
        "write_count": write_count,
        "avg_read_speed_bps": avg_read_speed_bps,
        "avg_write_speed_bps": avg_write_speed_bps,
        "read_lba_variance": read_lba_variance,
        "write_lba_variance": write_lba_variance,
        "window_event_count": len(events_in_window)
    }

def parse_blktrace_line(line):
    """Parses a line of blktrace output based on the defined format."""
    try:
        parts = line.strip().split()
        # Expected format: Timestamp Action RWBS LBA Size ProcessName
        if len(parts) < 6:
            return None # Not enough parts

        timestamp_str, action, rwbs, lba_str, size_str = parts[:5]

        # We only care about *completed* operations ('C') for calculating speed/counts
        if action != 'C':
            return None

        op_type = None
        if 'R' in rwbs:
            op_type = 'R'
        elif 'W' in rwbs:
            op_type = 'W'
        else:
            return None # Not a read or write completion we're tracking

        timestamp = float(timestamp_str)
        lba = int(lba_str)
        size = int(size_str)

        return TraceEvent(timestamp=timestamp, op_type=op_type, lba=lba, size=size)

    except (ValueError, IndexError) as e:
        # Ignore lines that don't parse correctly
        # print(f"Warning: Could not parse line: {line.strip()} - Error: {e}", file=sys.stderr)
        return None

def main(device):
    """Main function to run blktrace and process its output."""
    if not os.path.exists(device):
        print(f"Error: Device '{device}' not found.", file=sys.stderr)
        sys.exit(1)
    #if not os.path.isblk(device):
    #     print(f"Error: '{device}' is not a block device.", file=sys.stderr)
    #     sys.exit(1)

    # --- Check for blktrace ---
    try:
        subprocess.run(['blktrace', '-V'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (FileNotFoundError, subprocess.CalledProcessError):
         print("Error: 'blktrace' command not found or not executable. Please install it.", file=sys.stderr)
         sys.exit(1)


    # --- Start blktrace ---
    # -d device: Target device
    # -o - : Output to stdout
    # -f format: Specify output format
    # Use stdbuf to ensure line buffering from blktrace even through pipes
    command = ['stdbuf', '-oL', 'blktrace', '-d', device, '-o', '-', '-f', BLKTRACE_FORMAT]
    print(f"Starting blktrace: {' '.join(command)}")
    print(f"Monitoring device: {device}")
    print(f"Using sliding window: {WINDOW_DURATION_SEC} seconds")
    print("Press Ctrl+C to stop.")

    process = None
    try:
        # Using Popen to manage the process and read its output
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

        # Deque to hold events within the sliding window
        events = deque()
        last_print_time = 0

        # Use select for potentially more responsive reading, especially if blktrace output is bursty
        poller = select.poll()
        poller.register(process.stdout, select.POLLIN)

        while True:
            # Check if blktrace exited unexpectedly
            if process.poll() is not None:
                 print("\nError: blktrace process terminated unexpectedly.", file=sys.stderr)
                 stderr_output = process.stderr.read()
                 if stderr_output:
                     print("--- blktrace stderr ---", file=sys.stderr)
                     print(stderr_output, file=sys.stderr)
                     print("-----------------------", file=sys.stderr)
                 break # Exit main loop

            # Wait for data for a short time (e.g., 1 second)
            if poller.poll(1000): # Timeout in milliseconds
                line = process.stdout.readline()
                if not line: # End of stream
                    break

                event = parse_blktrace_line(line)
                if event:
                    current_time = event.timestamp
                    events.append(event)

                    # Remove events older than the window duration relative to the *newest* event
                    window_start_time = current_time - WINDOW_DURATION_SEC
                    while events and events[0].timestamp < window_start_time:
                        events.popleft()

                    # --- Calculate and Print Metrics Periodically ---
                    # Print roughly every second, based on the event timestamps
                    if current_time - last_print_time >= 1.0:
                         if events:
                            metrics = calculate_metrics(events, WINDOW_DURATION_SEC)
                            latest_event_time = events[-1].timestamp
                            oldest_event_time = events[0].timestamp
                            actual_span = latest_event_time - oldest_event_time

                            print("-" * 60)
                            print(f"Window ending ~ {latest_event_time:.3f} (span: {actual_span:.3f}s, {metrics['window_event_count']} events)")
                            print(f"  Read Count : {metrics['read_count']:>6d} | Write Count : {metrics['write_count']:>6d}")
                            print(f"  Read Speed : {metrics['avg_read_speed_bps']/1024/1024:>8.2f} MB/s | Write Speed : {metrics['avg_write_speed_bps']/1024/1024:>8.2f} MB/s")
                            print(f"  Read LBA Var: {metrics['read_lba_variance']:>12.2e} | Write LBA Var: {metrics['write_lba_variance']:>12.2e}")
                            last_print_time = current_time
                         else:
                            # Print zeros if window is empty but time has passed
                            print("-" * 60)
                            print(f"Window ending ~ {current_time:.3f} (span: 0.000s, 0 events)")
                            print(f"  Read Count : {0:>6d} | Write Count : {0:>6d}")
                            print(f"  Read Speed : {0.0:>8.2f} MB/s | Write Speed : {0.0:>8.2f} MB/s")
                            print(f"  Read LBA Var: {0.0:>12.2e} | Write LBA Var: {0.0:>12.2e}")
                            last_print_time = current_time
            # else:
                # No data received in the last second, could print empty stats if desired
                # current_real_time = time.time()
                # if current_real_time - last_print_time >= 1.0:
                #      # Similar print block as above, but with zeros and using real time
                #      last_print_time = current_real_time


    except KeyboardInterrupt:
        print("\nStopping blktrace...")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)
    finally:
        if process:
            if process.poll() is None: # If process is still running
                try:
                    process.terminate() # Send SIGTERM
                    time.sleep(0.5) # Give it a moment to exit
                    if process.poll() is None: # Still running?
                         print("blktrace did not terminate gracefully, sending SIGKILL...")
                         process.kill() # Send SIGKILL
                    process.wait(timeout=1) # Wait for process to avoid zombie
                    print("blktrace stopped.")
                except Exception as e_term:
                     print(f"Error during blktrace termination: {e_term}", file=sys.stderr)
            # Read any remaining output/errors
            stderr_output = process.stderr.read()
            if stderr_output:
                 print("--- blktrace stderr ---", file=sys.stderr)
                 print(stderr_output, file=sys.stderr)
                 print("-----------------------", file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Monitor block device I/O using blktrace and calculate metrics in sliding windows.",
        epilog="Requires 'blktrace' installed and likely root privileges to run."
                 " Example: sudo python your_script_name.py /dev/sda"
    )
    parser.add_argument("device", help="The block device to monitor (e.g., /dev/sda, /dev/nvme0n1)")
    args = parser.parse_args()

    # Check for root privileges if accessing block devices directly often requires it
    if os.geteuid() != 0:
         print("Warning: This script might need root privileges (sudo) to run blktrace on block devices.", file=sys.stderr)

    main(args.device)

