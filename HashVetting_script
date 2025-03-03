import  hashlib
from pathlib import Path
import logging
import os
import sys

# Set up logging
logging.basicConfig(filename='duplicate_report.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def load_hashes_from_file(file_path):
    with open(file_path, 'r') as file:
        return {line.strip().lower() for line in file if line.strip()}

def find_and_compare_hashes(directory, input_hashes, algorithm='md5'):
    file_hashes = {}
    matches = []
    deleted_files_info = []

    print(f"Scanning directory: {directory} using {algorithm} algorithm")

    for file_path in Path(directory).rglob('*'):
        if file_path.is_file():
            try:
                with file_path.open('rb') as f:
                    # Create a new hash object using the specified algorithm
                    hasher = hashlib.new(algorithm)
                    # Read the file in chunks to avoid memory issues with large files
                    while chunk := f.read(8192):
                        hasher.update(chunk)
                    file_hash = hasher.hexdigest().lower()

                    # Debug: Print the file hash
                    print(f"File: {file_path}, Hash: {file_hash}")

                    # Compare with input hashes
                    if file_hash in input_hashes:
                        logging.info(f"Match found: {file_path}")
                        print(f"Match found: {file_path}")
                        matches.append((file_path, file_hash))

                    # Store the hash for potential duplicate detection
                    if file_hash in file_hashes:
                        logging.info(f"Duplicate found: {file_path} (deleting)")
                        print(f"Duplicate found and deleted: {file_path}, Hash: {file_hash}")
                        file_path.unlink()  # Delete the duplicate file
                        deleted_files_info.append((file_path, file_hash))
                    else:
                        file_hashes[file_hash] = file_path
            except Exception as e:
                logging.error(f"Error processing file {file_path}: {e}")
                print(f"Error processing file {file_path}: {e}")

    # Generate a report
    with open('matches_report.txt', 'w') as report_file:
        report_file.write("Matched Files Report\n")
        report_file.write("====================\n")
        for match, hash in matches:
            report_file.write(f"File: {match}, Hash: {hash}\n")
        report_file.write("\nDeleted Files:\n")
        report_file.write("====================\n")
        for file_path, file_hash in deleted_files_info:
            report_file.write(f"File: {file_path}, Hash: {file_hash}\n")
        report_file.write(f"\nTotal files deleted: {len(deleted_files_info)}\n")

    print(f"Scan complete. {len(deleted_files_info)} files deleted. Check 'matches_report.txt' for details.")

# Load hashes from file
print("Loading hashes from: C:\\Users\\User\\Documents\\hashScript\\Hash_Test.txt")
input_hashes = load_hashes_from_file(r"C:\Users\User\Documents\\Hash_Test.txt")

# Debug: Print loaded hashes
print("Loaded hashes:")
for h in input_hashes:
    print(h)

# Example usage
# You can specify the algorithm as a command-line argument, e.g., python hash_find.py sha1
algorithm = sys.argv[1] if len(sys.argv) > 1 else 'md5'
find_and_compare_hashes(r'E:\TESTING_HASH', input_hashes, algorithm)

print(os.listdir(r'C:\Users\User\Documents\hashScript'))
