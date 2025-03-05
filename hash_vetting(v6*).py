import hashlib
from pathlib import Path
import logging
import os
import sys
import time
import re
import psutil
import ctypes
from diskcache import Cache
import win32api
import win32security
import win32con

# Maintain original paths from your script
HASH_FILE_PATH = r"C:\Users\User\Documents\Hash_Test.txt"
TARGET_FOLDER = r"E:\TESTING_HASH"
SCRIPT_FOLDER = r"C:\Users\User\Documents\hashScript"

# Configure logging as per original
logging.basicConfig(
    filename='duplicate_report.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def load_hashes_from_file(file_path):
    with open(file_path, 'r') as file:
        return {line.strip().lower() for line in file if line.strip()}

def set_windows_permissions(file_path):
    """Enhanced Windows permission handling"""
    try:
        user_sid = win32security.LookupAccountName(None, win32api.GetUserName())[0]
        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            win32con.FILE_ALL_ACCESS,
            user_sid
        )
        win32security.SetNamedSecurityInfo(
            str(file_path),
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION,
            None, None, dacl, None
        )
    except Exception as e:
        logging.error(f"Permission error: {str(e)}")

def secure_delete(file_path, max_retries=5):
    """Enhanced deletion with verification"""
    original_path = file_path.resolve()
    for attempt in range(max_retries):
        try:
            if not file_path.exists():
                return True
            
            set_windows_permissions(file_path)
            file_path.chmod(0o777)
            file_path.unlink()
            
            # Verify deletion
            if not file_path.exists():
                return True
            
            logging.warning(f"Verification failed, retrying {file_path}")
            time.sleep(1 * (attempt + 1))
        except Exception as e:
            logging.error(f"Attempt {attempt+1} failed: {str(e)}")
            time.sleep(2 * (attempt + 1))
    
    logging.error(f"Permanent deletion failure: {file_path}")
    return False

def find_and_compare_hashes(directory, input_hashes, algorithms=['md5', 'sha1']):
    file_hashes = {}
    matches = []
    deleted_files_info = []
    failed_deletions = []
    failed_scans = []
    total_files_processed = 0

    print(f"Scanning directory: {directory} using algorithms: {', '.join(algorithms)}")

    for file_path in Path(directory).rglob('*'):
        if file_path.is_file():
            total_files_processed += 1
            try:
                file_hashes_for_file = {}
                for algorithm in algorithms:
                    with file_path.open('rb') as f:
                        hasher = hashlib.new(algorithm)
                        while chunk := f.read(8192):
                            hasher.update(chunk)
                        file_hash = hasher.hexdigest().lower()
                        file_hashes_for_file[algorithm] = file_hash

                        print(f"File: {file_path}, Algorithm: {algorithm}, Hash: {file_hash}")

                        if file_hash in input_hashes:
                            logging.info(f"Match found: {file_path} using {algorithm}")
                            print(f"Match found: {file_path} using {algorithm}")
                            matches.append((file_path, file_hash, algorithm))

                            # Attempt deletion with verification
                            if secure_delete(file_path):
                                deleted_files_info.append((file_path, file_hash, algorithm))
                                print(f"Successfully deleted: {file_path}")
                            else:
                                failed_deletions.append((file_path, file_hash, algorithm, "Deletion failed after retries"))
                                print(f"Failed to delete: {file_path}")

                for algorithm, file_hash in file_hashes_for_file.items():
                    if file_hash not in file_hashes:
                        file_hashes[file_hash] = file_path
                        logging.debug(f"File added to hash list: {file_path} with hash {file_hash}")
                        
            except Exception as e:
                logging.error(f"Error processing file {file_path}: {e}")
                print(f"Error processing file {file_path}: {e}")
                failed_scans.append((file_path, str(e)))

    # Generate report with original formatting
    with open('matches_report.txt', 'w') as report_file:
        report_file.write("Matched Files Report\n")
        report_file.write("====================\n")
        report_file.write(f"Total files processed: {total_files_processed}\n")
        report_file.write(f"Total files matched: {len(matches)}\n")
        report_file.write(f"Total files deleted: {len(deleted_files_info)}\n")
        
        report_file.write("\nMatched Files:\n")
        report_file.write("====================\n")
        for match, hash, algorithm in matches:
            report_file.write(f"File: {match}, Hash: {hash}, Algorithm: {algorithm}\n")
        
        report_file.write("\nDeleted Files:\n")
        report_file.write("====================\n")
        for file_path, file_hash, algorithm in deleted_files_info:
            report_file.write(f"File: {file_path}, Hash: {file_hash}, Algorithm: {algorithm}\n")
        
        report_file.write("\nFailed Deletions:\n")
        report_file.write("====================\n")
        for file_path, file_hash, algorithm, error in failed_deletions:
            report_file.write(f"File: {file_path}, Hash: {file_hash}, Algorithm: {algorithm}, Error: {error}\n")

        report_file.write("\nFailed Scans:\n")
        report_file.write("====================\n")
        for file_path, error in failed_scans:
            report_file.write(f"File: {file_path}, Error: {error}\n")

    print(f"Scan complete. {len(deleted_files_info)} files deleted. Check 'matches_report.txt' for details.")
    print("Hashes of deleted files:")
    for file_path, file_hash, algorithm in deleted_files_info:
        print(f"File: {file_path}, Hash: {file_hash}, Algorithm: {algorithm}")

# Maintain original startup sequence
print("Loading hashes from: C:\\Users\\User\\Documents\\hashScript\\Hash_Test.txt")
input_hashes = load_hashes_from_file(HASH_FILE_PATH)

print("Loaded hashes:")
for h in input_hashes:
    print(h)

print("All hash numbers from Hash_Test.txt:")
for hash_number in input_hashes:
    print(hash_number)

find_and_compare_hashes(Path(TARGET_FOLDER), input_hashes)
print(os.listdir(SCRIPT_FOLDER))
