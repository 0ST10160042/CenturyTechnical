import hashlib
from pathlib import Path
import logging
import os
import sys
import time
import re
import psutil
import ctypes
import shutil
from diskcache import Cache
import win32api
import win32security
import win32con

# Maintain original paths from your script
HASH_FILE_PATH = r"C:\\Users\\User\\Documents\\Hash_Test.txt"
TARGET_FOLDER = r"E:\\TESTING_HASH"
SCRIPT_FOLDER = r"C:\\Users\\User\\Documents\\hashScript"
QUARANTINE_FOLDER = r"C:\\Users\\User\\Documents\\hashScript\\Removed_files"

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

def secure_move(file_path):
    """Move file to quarantine with conflict resolution"""
    original_path = file_path.resolve()
    dest_path = Path(QUARANTINE_FOLDER) / file_path.name
    attempt = 1
    
    while True:
        try:
            if not dest_path.exists():
                # Optionally reset permissions before moving
                set_windows_permissions(file_path)
                shutil.move(str(original_path), str(dest_path))
                return dest_path, None
            
            # Handle filename conflicts
            new_name = f"{file_path.stem}_conflict{attempt}{file_path.suffix}"
            dest_path = dest_path.with_name(new_name)
            attempt += 1
            
        except Exception as e:
            return None, str(e)

def compute_hashes(file_path, algorithms=['md5', 'sha1']):
    """Compute hashes for a file using specified algorithms."""
    hashes = {}
    with file_path.open('rb') as f:
        data = f.read()  # Read once into memory
        for algo in algorithms:
            hasher = hashlib.new(algo)
            hasher.update(data)
            hashes[algo] = hasher.hexdigest().lower()
    return hashes

def find_and_compare_hashes(directory, input_hashes, algorithms=['md5', 'sha1']):
    file_hashes = {}
    matches = []
    moved_files_info = []
    failed_moves = []
    failed_scans = []
    total_files_processed = 0

    print(f"Scanning directory: {directory} using algorithms: {', '.join(algorithms)}")
    
    # Ensure quarantine folder exists
    Path(QUARANTINE_FOLDER).mkdir(parents=True, exist_ok=True)

    for file_path in Path(directory).rglob('*'):
        if file_path.is_file():
            total_files_processed += 1
            try:
                file_hashes_for_file = compute_hashes(file_path, algorithms)

                for algorithm, file_hash in file_hashes_for_file.items():
                    print(f"File: {file_path}, Algorithm: {algorithm}, Hash: {file_hash}")

                    if file_hash in input_hashes:
                        logging.info(f"Match found: {file_path} using {algorithm}")
                        print(f"Match found: {file_path} using {algorithm}")
                        matches.append((file_path, file_hash, algorithm))

                        # Attempt secure move
                        new_path, error = secure_move(file_path)
                        if new_path:
                            moved_files_info.append((file_path, new_path, file_hash, algorithm))
                            print(f"Moved file: {file_path} -> {new_path}")
                        else:
                            failed_moves.append((file_path, file_hash, algorithm, error))
                            print(f"Failed to move: {file_path} - {error}")

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
        report_file.write(f"Total files moved: {len(moved_files_info)}\n")
        
        report_file.write("\nMatched Files:\n")
        report_file.write("====================\n")
        for match, hash, algorithm in matches:
            report_file.write(f"File: {match}, Hash: {hash}, Algorithm: {algorithm}\n")
        
        report_file.write("\nMoved Files:\n")
        report_file.write("====================\n")
        for orig_path, new_path, file_hash, algorithm in moved_files_info:
            report_file.write(f"Original: {orig_path}\nMoved To: {new_path}\n")
            report_file.write(f"Hash ({algorithm.upper()}): {file_hash}\n\n")
        
        report_file.write("\nFailed Moves:\n")
        report_file.write("====================\n")
        for file_path, file_hash, algorithm, error in failed_moves:
            report_file.write(f"File: {file_path}, Hash: {file_hash}, Algorithm: {algorithm}\n")
            report_file.write(f"Error: {error}\n\n")

        report_file.write("\nFailed Scans:\n")
        report_file.write("====================\n")
        for file_path, error in failed_scans:
            report_file.write(f"File: {file_path}, Error: {error}\n")

    print(f"Scan complete. {len(moved_files_info)} files moved to quarantine.")
    print("Hashes of moved files:")
    for orig_path, new_path, file_hash, algorithm in moved_files_info:
        print(f"Original: {orig_path} | New: {new_path} | {algorithm.upper()}: {file_hash}")

# Load hashes from file
hash_file_path = Path(HASH_FILE_PATH)

if not hash_file_path.exists():
    print(f"Error: The file {hash_file_path} does not exist.")
    sys.exit(1)

print(f"Loading hashes from: {hash_file_path}")
input_hashes = load_hashes_from_file(hash_file_path)

print("Loaded hashes:")
for h in input_hashes:
    print(h)

print("All hash numbers from Hash_Test.txt:")
for hash_number in input_hashes:
    print(hash_number)

find_and_compare_hashes(Path(TARGET_FOLDER), input_hashes)
print(os.listdir(SCRIPT_FOLDER))
