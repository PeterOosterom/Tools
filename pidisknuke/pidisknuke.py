#!/usr/bin/env python
import subprocess
import os
import time

def secure_erase_ssd(device):
    print(f"Secure erasing SSD: {device}")
    subprocess.run(["nvme", "format", "--ses=1", "--ps=1", device])

def fill_with_zeros_hdd(device):
    print(f"Filling HDD with zeros: {device}")
    subprocess.run(["hdparm", "--security-erase", "NULL", device])

def wipe_disk(device):
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

def find_usb_devices():
    result = subprocess.run(["lsblk", "--output", "KNAME,TRAN", "--noheadings", "--list"], capture_output=True, text=True)
    lines = result.stdout.strip().split('\n')
    usb_devices = [line.split()[0] for line in lines if "usb" in line.lower()]
    return usb_devices

def main():
    # Monitor for disk insertion
    while True:
        usb_devices = find_usb_devices()
        
        if usb_devices:
            for device in usb_devices:
                disk_path = f"/dev/{device}"
                print(f"Disk detected: {disk_path}")
                wipe_disk(disk_path)
                print("Wipe process completed.")
                
                # Output to a file (you can customize the file path)
                with open("/path/to/output.log", "a") as f:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}: Wipe process completed for {disk_path}\n")

                # Optional: Eject the disk after wiping
                subprocess.run(["udisksctl", "eject", "-b", disk_path])

                # Wait for the disk to be removed
                while os.path.exists(disk_path):
                    time.sleep(1)
        else:
            time.sleep(1)

if __name__ == "__main__":
    main()
