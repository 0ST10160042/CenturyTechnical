import hashlib
from pathlib import Path
import logging
import os
import sys
import time
import shutil
import win32api
import win32security
import win32con

# ------ CONSTANTS AND PATHS ------
HASH_FILE_PATH = r"C:\Users\User\Documents\Hash_Test.txt"
TARGET_FOLDER = r"E:\TESTING_HASH"
SCRIPT_FOLDER = r"C:\Users\User\Documents\hashScript"
QUARANTINE_FOLDER = r"C:\Users\User\Documents\hashScript\Removed_files"

# ------ FUNCTION DEFINITIONS ------
def load_hashes_from_file(file_path):
    """Load and normalize hashes from file with validation"""
    try:
        with open(file_path, 'r') as file:
            return {line.strip().lower() for line in file if line.strip()}
    except Exception as e:
        logging.critical(f"Failed to load hash file: {str(e)}")
        raise

def set_windows_permissions(file_path):
    """Set full control permissions using Windows security APIs"""
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
        raise

def is_system_file(path):
    """Check if file has system attribute"""
    try:
        attrs = win32api.GetFileAttributes(str(path))
        return bool(attrs & win32con.FILE_ATTRIBUTE_SYSTEM)
    except:
        return False

def handle_long_path(path):
    """Convert path to extended-length Windows format"""
    return "\\\\?\\" + str(Path(path).resolve()) if len(str(path)) > 240 else path

def secure_move(file_path, max_retries=5, retry_delay=1):
    """Robust file relocation with cross-filesystem support and verification"""
    src = Path(handle_long_path(file_path))
    dest_dir = Path(handle_long_path(QUARANTINE_FOLDER))
    dest_dir.mkdir(parents=True, exist_ok=True)
    
    original_name = src.name
    base_dest = dest_dir / original_name
    conflict_num = 0
    attempt = 0

    if is_system_file(src):
        logging.warning(f"Skipping system file: {src}")
        return None

    if len(str(src)) > 240:
        logging.info(f"Processing long path file: {src}")

    while attempt <= max_retries:
        try:
            current_dest = base_dest.with_name(f"{base_dest.stem}_conflict{conflict_num}{base_dest.suffix}" if conflict_num else base_dest.name)
            current_dest = Path(handle_long_path(current_dest))

            # Cross-filesystem move with verification
            shutil.move(str(src), str(current_dest))

            # Delayed verification with multiple checks
            verified = False
            for _ in range(5):
                time.sleep(0.5)
                if not src.exists() and current_dest.exists():
                    verified = True
                    break
            
            if not verified:
                raise RuntimeError(f"Verification failed for {src} -> {current_dest}")

            logging.info(f"Successfully moved: {src} -> {current_dest}")
            return current_dest

        except PermissionError as pe:
            attempt += 1
            logging.warning(f"Attempt {attempt}/{max_retries} failed (PermissionError): {pe}")
            time.sleep(retry_delay * (2 ** attempt))
            if attempt == max_retries:
                logging.error(f"Permanent move failure: {src}")
                return None

        except FileExistsError:
            conflict_num += 1
            logging.info(f"Resolving name conflict for: {src.name}")

        except Exception as e:
            logging.error(f"Move error: {type(e).__name__}: {str(e)}")
            if current_dest.exists():
                try:
                    current_dest.unlink()
                except Exception as cleanup_err:
                    logging.error(f"Cleanup failed: {cleanup_err}")
            return None

    return None

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

                            # Attempt secure move
                            new_path, error = secure_move(file_path)
                            if new_path:
                                moved_files_info.append((file_path, new_path, file_hash, algorithm))
                                print(f"Moved file: {file_path} -> {new_path}")
                            else:
                                failed_moves.append((file_path, file_hash, algorithm, error))
                                print(f"Failed to move: {file_path} - {error}")

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

# ------ MAIN EXECUTION ------
if __name__ == "__main__":
    # Initialize logging
    logging.basicConfig(
        filename=Path(SCRIPT_FOLDER) / 'file_operations.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Validate paths
    print("Validating system paths...")
    print(f"Target exists: {Path(TARGET_FOLDER).exists()}")
    print(f"Quarantine writable: {os.access(QUARANTINE_FOLDER, os.W_OK)}")

    # Load hashes
    try:
        print(f"\nLoading hashes from: {HASH_FILE_PATH}")
        input_hashes = load_hashes_from_file(HASH_FILE_PATH)
        print(f"Loaded {len(input_hashes)} valid hashes")
    except Exception as e:
        print(f"Critical error: {str(e)}")
        sys.exit(1)

    # Process files
    try:
        find_and_compare_hashes(Path(TARGET_FOLDER), input_hashes)
        print(f"\nOperation complete. Moved {len(moved_files_info)} files.")
        print(f"Quarantine contents: {os.listdir(QUARANTINE_FOLDER)}")
    except Exception as e:
        print(f"Fatal error during processing: {str(e)}")
      
