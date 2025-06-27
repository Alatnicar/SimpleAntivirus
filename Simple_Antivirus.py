import os
import time
import hashlib
import requests
import psutil
import win32api
import win32con
import win32security
import win32process
import win32event
import win32com.client
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
from pathlib import Path
import logging
import threading
import queue
import shutil

# Configuration
API_KEY = "Your_virustotal_API_Key_here"  # Replace with your VirusTotal API key
QUARANTINE_PATH = Path(r"C:\ProgramData\Antivirus\Quarantine")
LOG_FILE = Path(r"C:\ProgramData\Antivirus\antivirus.log")
CHECK_INTERVAL = 5  # Seconds between processing batches of files

# Ensure log directory exists before setting up logging
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# VirusTotal API endpoints
VT_FILE_REPORT_URL = "https://www.virustotal.com/api/v3/files/{}"
VT_FILE_SCAN_URL = "https://www.virustotal.com/api/v3/files"

# Queue for processing files
file_queue = queue.Queue()

def get_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating hash for {file_path}: {e}")
        return None

def is_dll_unsigned(file_path):
    """Check if a DLL is unsigned."""
    try:
        file_path = str(file_path)
        if not file_path.lower().endswith(".dll"):
            return False
        sig_info = win32api.GetFileVersionInfo(file_path, "\\")
        return False  # If no exception, assume signed (simplified check)
    except Exception:
        return True  # If error (e.g., no signature), treat as unsigned

def take_file_ownership(file_path):
    """Take ownership of a file for the current user."""
    try:
        user_sid = win32security.GetTokenInformation(
            win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY),
            win32security.TokenUser
        )[0]
        security_descriptor = win32security.GetFileSecurity(
            file_path, win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION
        )
        security_descriptor.SetSecurityDescriptorOwner(user_sid, False)
        win32security.SetFileSecurity(
            file_path, win32security.OWNER_SECURITY_INFORMATION, security_descriptor
        )
        logging.info(f"Ownership taken for {file_path}")
    except Exception as e:
        logging.error(f"Error taking ownership of {file_path}: {e}")

def remove_file_permissions(file_path):
    """Remove all permissions (inherited and explicit) from a file."""
    try:
        security_descriptor = win32security.SECURITY_DESCRIPTOR()
        win32security.SetFileSecurity(
            file_path, win32security.DACL_SECURITY_INFORMATION, security_descriptor
        )
        logging.info(f"Permissions removed for {file_path}")
    except Exception as e:
        logging.error(f"Error removing permissions for {file_path}: {e}")

def terminate_locking_processes(file_path):
    """Terminate processes locking a file, restarting explorer.exe if needed."""
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                for file in proc.open_files():
                    if file.path.lower() == file_path.lower():
                        parent = psutil.Process(proc.pid).parent()
                        proc.terminate()
                        proc.wait(timeout=3)
                        logging.info(f"Terminated process {proc.name()} (PID: {proc.pid}) locking {file_path}")
                        if parent and parent.name().lower() == "explorer.exe":
                            shell = win32com.client.Dispatch("WScript.Shell")
                            shell.Run("taskkill /IM explorer.exe /F", 0, True)
                            time.sleep(1)
                            shell.Run("explorer.exe", 0, True)
                            logging.info("Restarted explorer.exe")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        logging.error(f"Error terminating processes for {file_path}: {e}")

def move_to_quarantine(file_path):
    """Move a file to quarantine with unique folder name."""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        file_name = Path(file_path).name
        dest_folder = QUARANTINE_PATH / f"{file_name}_{timestamp}"
        dest_folder.mkdir(parents=True, exist_ok=True)
        dest_path = dest_folder / file_name

        take_file_ownership(file_path)
        remove_file_permissions(file_path)
        terminate_locking_processes(file_path)

        shutil.move(file_path, dest_path)
        logging.info(f"Moved {file_path} to {dest_path}")
        return True
    except Exception as e:
        logging.error(f"Error moving {file_path} to quarantine: {e}")
        return False

def check_virustotal(file_path, file_hash):
    """Check file hash with VirusTotal, upload if necessary."""
    headers = {"x-apikey": API_KEY}
    try:
        # Check if hash exists
        response = requests.get(VT_FILE_REPORT_URL.format(file_hash), headers=headers)
        if response.status_code == 200:
            result = response.json()
            stats = result["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            if malicious > 0:
                logging.info(f"File {file_path} flagged as malicious by VirusTotal")
                return True
            return False
        elif response.status_code == 404:
            # Hash not found, upload file
            with open(file_path, "rb") as f:
                files = {"file": (Path(file_path).name, f)}
                response = requests.post(VT_FILE_SCAN_URL, headers=headers, files=files)
                if response.status_code == 200:
                    # Wait for analysis
                    analysis_id = response.json()["data"]["id"]
                    for _ in range(5):  # Retry up to 5 times
                        time.sleep(10)  # Wait for VirusTotal to process
                        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                        response = requests.get(analysis_url, headers=headers)
                        if response.status_code == 200:
                            result = response.json()
                            stats = result["data"]["attributes"]["stats"]
                            malicious = stats.get("malicious", 0)
                            if malicious > 0:
                                logging.info(f"Uploaded file {file_path} flagged as malicious")
                                return True
                            return False
                        time.sleep(5)
                    logging.warning(f"Analysis timeout for {file_path}")
                    return False
                else:
                    logging.error(f"Error uploading {file_path} to VirusTotal: {response.text}")
                    return False
        elif response.status_code == 429:
            logging.warning(f"Rate limit hit for {file_path}. Retrying after delay.")
            time.sleep(60)  # Wait for rate limit reset
            return check_virustotal(file_path, file_hash)  # Retry
        else:
            logging.error(f"Error checking {file_path} with VirusTotal: {response.text}")
            return False
    except Exception as e:
        logging.error(f"Error in VirusTotal check for {file_path}: {e}")
        return False

def scan_existing_files():
    """Scan all existing files on local, removable, and network drives."""
    drives = [d for d in win32api.GetLogicalDriveStrings().split('\0') if d]
    for drive in drives:
        try:
            drive_type = win32api.GetDriveType(drive)
            if drive_type in (win32con.DRIVE_FIXED, win32con.DRIVE_REMOVABLE, win32con.DRIVE_REMOTE):
                for root, _, files in os.walk(drive):
                    for file in files:
                        file_path = Path(root) / file
                        file_queue.put(str(file_path))
        except Exception as e:
            logging.error(f"Error scanning drive {drive}: {e}")

class FileEventHandler(FileSystemEventHandler):
    """Handle file system events for creation and modification."""
    def on_created(self, event):
        if not event.is_directory:
            file_queue.put(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            file_queue.put(event.src_path)

def process_file_queue():
    """Process files from the queue."""
    while True:
        try:
            file_path = file_queue.get(timeout=CHECK_INTERVAL)
            try:
                file_path = Path(file_path)
                if not file_path.exists():
                    logging.debug(f"File {file_path} does not exist, skipping")
                    continue

                # Immediate quarantine for unsigned DLLs
                if is_dll_unsigned(file_path):
                    logging.info(f"Quarantining unsigned DLL: {file_path}")
                    move_to_quarantine(file_path)
                else:
                    # VirusTotal check
                    file_hash = get_file_hash(file_path)
                    if file_hash and check_virustotal(file_path, file_hash):
                        move_to_quarantine(file_path)
            finally:
                file_queue.task_done()  # Only call task_done after processing
        except queue.Empty:
            continue
        except Exception as e:
            logging.error(f"Error processing file {file_path}: {e}")

def setup_observers():
    """Set up file system observers for all drives."""
    observer = Observer()
    drives = [d for d in win32api.GetLogicalDriveStrings().split('\0') if d]
    for drive in drives:
        try:
            drive_type = win32api.GetDriveType(drive)
            if drive_type in (win32con.DRIVE_FIXED, win32con.DRIVE_REMOVABLE, win32con.DRIVE_REMOTE):
                event_handler = FileEventHandler()
                observer.schedule(event_handler, drive, recursive=True)
                logging.info(f"Monitoring drive: {drive}")
        except Exception as e:
            logging.error(f"Error setting up observer for {drive}: {e}")
    observer.start()
    return observer

def main():
    """Main function to initialize and run the antivirus."""
    logging.info("Simple Antivirus by Gorstak started")
    
    # Create quarantine folder
    QUARANTINE_PATH.mkdir(parents=True, exist_ok=True)

    # Start queue processing thread
    threading.Thread(target=process_file_queue, daemon=True).start()

    # Scan existing files
    threading.Thread(target=scan_existing_files, daemon=True).start()

    # Setup file system observers
    observer = setup_observers()

    try:
        while True:
            time.sleep(1)  # Keep the main thread alive
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    logging.info("Simple Antivirus stopped")

if __name__ == "__main__":
    main()
