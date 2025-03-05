import hashlib
from pathlib import Path
import logging
import os
import sys
import time
import re
import shutil
import win32api
import win32security
import win32con

# Configure paths
HASH_FILE_PATH = r"C:\Users\User\Documents\Hash_Test.txt"
TARGET_FOLDER = r"E:\TESTING_HASH"
SCRIPT_FOLDER = r"C:\Users\User\Documents\hashScript"
QUARANTINE_FOLDER = r"C:\Users\User\Documents\hashScript\Removed_files"

# Configure logging
logging.basicConfig(
    filename='file_operations.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def normalize_path(path):
    """Convert path to lowercase string for consistent comparisons"""
    return str(path.resolve()).lower()

def verify_directory_access(path):
    """Check write permissions for quarantine folder"""
    try:
        test_file = Path(path) / 'permission_test.tmp'
        test_file.touch()
        test_file.unlink()
        return True
    except Exception as e:
        logging.critical(f"Directory access error: {str(e)}")
        return False

def load_hashes_from_file(file_path):
    """Load and normalize hashes with validation"""
    try:
        with open(file_path, 'r') as file:
            return {line.strip().lower() for line in file if line.strip()}
    except Exception as e:
        logging.error(f"Hash file error: {str(e)}")
        sys.exit(1)

def secure_move(file_path):
    """Enhanced file moving with verification"""
    original_path = normalize_path(file_path)
    dest_folder = Path(QUARANTINE_FOLDER)
    dest_path = dest_folder / file_path.name
    attempt = 0
    max_attempts = 3

    while attempt < max_attempts:
        current_dest = dest_path.with_name(f"{dest_path.stem}_{attempt}{dest_path.suffix}") if attempt > 0 else dest_path
        try:
            # Create parent directories if needed
            current_dest.parent.mkdir(parents=True, exist_ok=True)
            
            # Move and verify
            shutil.move(str(file_path), str(current_dest))
            os.sync()  # Force write to disk
            
            # Verification check
            if current_dest.exists():
                logging.info(f"Moved verified: {original_path} -> {normalize_path(current_dest)}")
                return current_dest, None
                
            attempt += 1
            time.sleep(0.5)
            
        except Exception as e:
            logging.error(f"Move attempt {attempt} failed: {str(e)}")
            attempt += 1
            time.sleep(1)

    return None, f"Failed after {max_attempts} attempts"

def generate_physical_verification_report():
    """Cross-reference actual files with move records"""
    moved_files = []
    quarantine_path = Path(QUARANTINE_FOLDER)
    
    for item in quarantine_path.rglob('*'):
        if item.is_file():
            moved_files.append(normalize_path(item))
    
    return moved_files

def find_and_compare_hashes(directory, input_hashes, algorithms=['md5', 'sha1']):
    """Main processing function with enhanced verification"""
    # Initialize tracking containers
    matches = []
    moved_records = []
    failed_operations = []
    physical_verification = []

    # Verify directory access first
    if not verify_directory_access(QUARANTINE_FOLDER):
        print("FATAL: No write access to quarantine directory")
        sys.exit(1)

    print(f"Initiating scan of: {directory}")
    start_time = time.time()

    try:
        # Process files
        for file_path in Path(directory).rglob('*'):
            if not file_path.is_file():
                continue

            current_file = normalize_path(file_path)
            file_hashes = {}

            try:
                # Calculate hashes
                for algorithm in algorithms:
                    with file_path.open('rb') as f:
                        hasher = hashlib.new(algorithm)
                        while chunk := f.read(8192):
                            hasher.update(chunk)
                        file_hash = hasher.hexdigest().lower()
                        file_hashes[algorithm] = file_hash

                        if file_hash in input_hashes:
                            matches.append((current_file, file_hash, algorithm))
                            logging.info(f"Hash match: {current_file} [{algorithm}]")

                            # Attempt secure move
                            dest_path, error = secure_move(file_path)
                            if dest_path:
                                moved_records.append({
                                    'original': current_file,
                                    'destination': normalize_path(dest_path),
                                    'hash': file_hash,
                                    'algorithm': algorithm
                                })
                            else:
                                failed_operations.append({
                                    'path': current_file,
                                    'error': error,
                                    'hash': file_hash
                                })

            except Exception as e:
                logging.error(f"Processing error: {current_file} - {str(e)}")
                failed_operations.append({
                    'path': current_file,
                    'error': str(e),
                    'hash': 'N/A'
                })

        # Physical verification
        physical_verification = generate_physical_verification_report()

    finally:
        # Generate comprehensive report
        with open('operation_report.txt', 'w') as report:
            report.write(f"File Processing Report\n{'='*40}\n")
            report.write(f"Scan duration: {time.time()-start_time:.2f} seconds\n")
            report.write(f"Files scanned: {sum(1 for _ in Path(directory).rglob('*'))}\n")
            report.write(f"Hash matches: {len(matches)}\n")
            report.write(f"Move attempts: {len(moved_records)}\n")
            report.write(f"Physically verified: {len(physical_verification)}\n\n")

            # Record physical verification results
            report.write("Verified Moved Files:\n")
            for path in physical_verification:
                report.write(f"{path}\n")

            # Record discrepancies
            report.write("\nDiscrepancies:\n")
            for record in moved_records:
                if record['destination'] not in physical_verification:
                    report.write(f"Missing: {record['original']} -> {record['destination']}\n")

            # Record failures
            if failed_operations:
                report.write("\nFailed Operations:\n")
                for fail in failed_operations:
                    report.write(f"{fail['path']} - {fail['error']}\n")

        print(f"Operation complete. Verification report: operation_report.txt")

# Execution flow
if __name__ == "__main__":
    print("Initializing file vetting system...\n")
    
    # Load and verify hashes
    print(f"Loading hash file: {HASH_FILE_PATH}")
    hash_set = load_hashes_from_file(HASH_FILE_PATH)
    print(f"Loaded {len(hash_set)} valid hashes")
    
    # Start processing
    find_and_compare_hashes(Path(TARGET_FOLDER), hash_set)
    
    # Final verification
    print("\nQuarantine directory contents:")
    print(os.listdir(QUARANTINE_FOLDER))
