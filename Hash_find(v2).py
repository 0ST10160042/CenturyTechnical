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



# Set up logging
logging.basicConfig(filename='duplicate_report.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def load_hashes_from_file(file_path):
    with open(file_path, 'r') as file:
        return {line.strip().lower() for line in file if line.strip()}

def find_and_compare_hashes(directory, input_hashes, algorithms=['md5', 'sha1']):
    file_hashes = {}
    matches = []
    deleted_files_info = []
    failed_deletions = []
    failed_scans = []

    print(f"Scanning directory: {directory} using algorithms: {', '.join(algorithms)}")

    for file_path in Path(directory).rglob('*'):
        if file_path.is_file():
            try:
                file_hashes_for_file = {}
                for algorithm in algorithms:
                    with file_path.open('rb') as f:
                        hasher = hashlib.new(algorithm)
                        while chunk := f.read(8192):
                            hasher.update(chunk)
                        file_hash = hasher.hexdigest().lower()
                        file_hashes_for_file[algorithm] = file_hash

                        # Debug: Print the file hash
                        print(f"File: {file_path}, Algorithm: {algorithm}, Hash: {file_hash}")

                        # Compare with input hashes
                        if file_hash in input_hashes:
                            logging.info(f"Match found: {file_path} using {algorithm}")
                            print(f"Match found: {file_path} using {algorithm}")
                            matches.append((file_path, file_hash, algorithm))

                # Check for duplicates and delete
                for algorithm, file_hash in file_hashes_for_file.items():
                    if file_hash in file_hashes:
                        try:
                            logging.info(f"Duplicate found: {file_path} (deleting)")
                            print(f"Duplicate found and deleted: {file_path}, Hash: {file_hash}")
                            file_path.unlink()  # Delete the duplicate file
                            deleted_files_info.append((file_path, file_hash, algorithm))
                        except Exception as e:
                            logging.error(f"Failed to delete file {file_path}: {e}")
                            failed_deletions.append((file_path, file_hash, algorithm, str(e)))
                    else:
                        file_hashes[file_hash] = file_path
                        logging.debug(f"File added to hash list: {file_path} with hash {file_hash}")
            except Exception as e:
                logging.error(f"Error processing file {file_path}: {e}")
                print(f"Error processing file {file_path}: {e}")
                failed_scans.append((file_path, str(e)))

    # Generate a report
      # Generate a report
    with open('matches_report.txt', 'w') as report_file:
        report_file.write("Matched Files Report\n")
        report_file.write("====================\n")
        for match, hash, algorithm in matches:
            report_file.write(f"File: {match}, Hash: {hash}, Algorithm: {algorithm}\n")
        report_file.write(f"\nTotal matched files: {len(matches)}\n")
        report_file.write(f"Total files processed: {len(file_hashes)}\n")
        report_file.write("\nDeleted Files:\n")
        report_file.write("====================\n")
        for file_path, file_hash, algorithm in deleted_files_info:
            report_file.write(f"File: {file_path}, Hash: {file_hash}, Algorithm: {algorithm}\n")
        report_file.write(f"\nTotal files deleted: {len(deleted_files_info)}\n")

        report_file.write("\nFailed Deletions:\n")
        report_file.write("====================\n")
        for file_path, file_hash, algorithm, error in failed_deletions:
            report_file.write(f"File: {file_path}, Hash: {file_hash}, Algorithm: {algorithm}, Error: {error}\n")

        report_file.write("\nFailed Scans:\n")
        report_file.write("====================\n")
        for file_path, error in failed_scans:
            report_file.write(f"File: {file_path}, Error: {error}\n")

    print(f"Scan complete. {len(deleted_files_info)} files deleted. Check 'matches_report.txt' for details.")

    # Print hashes of deleted files
    print("Hashes of deleted files:")
    for file_path, file_hash, algorithm in deleted_files_info:
        print(f"File: {file_path}, Hash: {file_hash}, Algorithm: {algorithm}")

# Load hashes from file
print("Loading hashes from: C:\\Users\\User\\Documents\\hashScript\\Hash_Test.txt")
input_hashes = load_hashes_from_file(r"C:\\Users\\User\\Documents\\Hash_Test.txt")

# Debug: Print loaded hashes
print("Loaded hashes:")
for h in input_hashes:
    print(h)

# Print all hash numbers from Hash_Test.txt
print("All hash numbers from Hash_Test.txt:")
for hash_number in input_hashes:
    print(hash_number)

# Example usage
find_and_compare_hashes(r'E:\TESTING_HASH', input_hashes)

print(os.listdir(r'C:\Users\User\Documents\hashScript'))
