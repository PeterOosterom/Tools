#!/usr/bin/env python

import subprocess
import os
import time
import signal
from multiprocessing import Process
import sys

LOG_FOLDER = "/var/log/pidisknuke"

def secure_erase_ssd(device):
    print(f"Secure erasing SSD: {device}")
    subprocess.run(["nvme", "format", "--ses=1", "--ps=1", device])

def fill_with_zeros_hdd(device):
    print(f"Filling HDD with zeros: {device}")
    subprocess.run(["dd", "if=/dev/zero", "of=" + device, "bs=1M", "status=progress"])

def wipe_disk(device, log_path):
    try:
        # Check if the device is an SSD or HDD
        result = subprocess.run(["lsblk", "--output", "TRAN", "--noheadings", "--raw", device], capture_output=True, text=True)
        disk_type = result.stdout.strip()

        if disk_type == "usb":
            if "nvme" in device:
                print(f"Disk type: SSD")
                secure_erase_ssd(device)
            else:
                print(f"Disk type: HDD")
                fill_with_zeros_hdd(device)
        else:
            print(f"Unsupported disk type: {disk_type}")

        # Output to a log file
        with open(log_path, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}: Wipe process completed for {device}\n")

        # Unmount the disk
        subprocess.run(["udisksctl", "unmount", "-b", device])

        # Wait for the disk to be removed
        while os.path.exists(device):
            time.sleep(1)
    except KeyboardInterrupt:
        print("Ctrl+C pressed. Exiting gracefully.")
        sys.exit(0)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.output.decode().strip()}")
        print(f"Disk {device} might be disconnected or not a mountable filesystem.")
    except Exception as ex:
        print(f"Error looking up object for device {device}: {ex}")

def find_usb_devices():
    result = subprocess.run(["lsblk", "--output", "KNAME,TRAN", "--noheadings", "--list"], capture_output=True, text=True)
    lines = result.stdout.strip().split('\n')
    usb_devices = [line.split()[0] for line in lines if "usb" in line.lower()]
    return usb_devices

def process_usb_devices(devices):
    processes = []
    for device in devices:
        disk_path = f"/dev/{device}"
        log_path = os.path.join(LOG_FOLDER, "pidisknuke_log.txt")
        
        print(f"Disk detected: {disk_path}")
        process = Process(target=wipe_disk, args=(disk_path, log_path))
        process.start()
        processes.append(process)

    # Wait for all processes to finish
    try:
        for process in processes:
            process.join()
    except KeyboardInterrupt:
        print("Ctrl+C pressed. Exiting gracefully.")
        sys.exit(0)

def main():
    print("Disk Wiping Script - Welcome!")
    print("This script securely wipes SSDs and fills HDDs with zeros.")
    print("Press Ctrl+C to exit.")

    # Create the log folder if it doesn't exist
    os.makedirs(LOG_FOLDER, exist_ok=True)

    # Set up the signal handler for Ctrl+C
    signal.signal(signal.SIGINT, lambda signum, frame: sys.exit(0))
    
    # Monitor for disk insertion
    while True:
        try:
            usb_devices = find_usb_devices()
            
            if usb_devices:
                process_usb_devices(usb_devices)

            # Wait for the disk to be inserted
            time.sleep(1)
        except Exception as e:
            print(f"An error occurred: {e}")
            print("Restarting the script...")
            time.sleep(1)

if __name__ == "__main__":
    main()
