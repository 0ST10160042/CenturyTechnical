import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from tkinterdnd2 import TkinterDnD, DND_FILES
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
from tqdm import tqdm
import threading
import pandas as pd
import json
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import Counter
import requests
from typing import Dict, Optional
from queue import Queue
from threading import Lock
import traceback
import logging.handlers


# Security and error handling classes
class PathSanitizer:
    """Prevents path traversal attacks and ensures safe path handling."""
    
    @staticmethod
    def sanitize_path(path):
        """Prevent path traversal attacks and normalize paths."""
        if not path:
            raise ValueError("Empty path provided")
            
        # Check for suspicious path patterns
        suspicious_patterns = ['..', '//', '\\\\', '~', '|', '*', '?', '<', '>', '"']
        path_str = str(path)
        for pattern in suspicious_patterns:
            if pattern in path_str:
                logging.warning(f"Potentially malicious path pattern detected: {pattern} in {path_str}")
                raise ValueError(f"Path contains suspicious pattern: {pattern}")
                
        # Resolve to absolute path to prevent relative path attacks
        resolved_path = Path(path).resolve()
        
        # Log the path resolution for security auditing
        logging.debug(f"Path sanitized: {path} → {resolved_path}")
        
        return resolved_path

    @staticmethod
    def is_safe_directory(directory, allowed_roots=None):
        """Checks if a directory is within allowed system roots."""
        if not allowed_roots:
            # Default to typical user directories
            # This could be expanded based on specific security requirements
            allowed_roots = [
                Path.home(),
                Path(os.environ.get('USERPROFILE', '')),
                Path(os.environ.get('TEMP', ''))
            ]
            
        directory_path = Path(directory).resolve()
        
        # Check if path is within any allowed root
        for root in allowed_roots:
            if root and str(directory_path).startswith(str(root)):
                return True
                
        logging.warning(f"Access attempt to restricted directory: {directory_path}")
        return False


class SecureFileHandler:
    """Provides secure file access methods with robust error handling."""
    
    @staticmethod
    def compute_hashes(file_path, algorithms=None, chunk_size=4096):
        """Securely compute file hashes using buffered reading to prevent memory issues."""
        if algorithms is None:
            algorithms = ['md5', 'sha1', 'sha256']
            
        # Initialize hashers for all requested algorithms
        hashers = {}
        for algo in algorithms:
            try:
                hashers[algo] = hashlib.new(algo)
            except ValueError:
                logging.warning(f"Unsupported hash algorithm: {algo}")
                continue
                
        if not hashers:
            raise ValueError("No valid hash algorithms specified")
            
        # Ensure file path is secure
        safe_path = PathSanitizer.sanitize_path(file_path)
        
        # Check if file exists and is readable
        if not safe_path.exists():
            raise FileNotFoundError(f"File not found: {safe_path}")
            
        # Check file size to avoid processing extremely large files
        file_size = safe_path.stat().st_size
        if file_size > 1024 * 1024 * 1024:  # 1GB limit
            logging.warning(f"File exceeds size limit: {file_size} bytes")
            raise ValueError(f"File too large: {file_size} bytes")
            
        # Process file in chunks to avoid memory issues
        try:
            with open(safe_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    for hasher in hashers.values():
                        hasher.update(chunk)
                        
            # Return computed hashes
            return {algo: hasher.hexdigest().lower() for algo, hasher in hashers.items()}
            
        except PermissionError:
            logging.error(f"Permission denied: {safe_path}")
            raise
        except IOError as e:
            logging.error(f"IO error reading file {safe_path}: {str(e)}")
            raise


class ErrorHandler:
    """Centralized error handling with contextual information and logging."""
    
    def __init__(self, app, logger=None):
        self.app = app
        self.logger = logger or logging.getLogger(__name__)
        self.error_codes = {}
        
    def handle(self, error, context="", display_to_user=True):
        """
        Handle errors with consistent logging and UI feedback.
        
        Args:
            error: The exception that occurred
            context: String describing where/why the error occurred
            display_to_user: Whether to show error in UI
            
        Returns:
            error_code: A unique code for this error instance
        """
        # Generate unique error code for reference
        error_code = abs(hash(str(error) + context + str(time.time())))
        error_code_short = error_code % 10000  # Shorter code for user display
        
        # Format traceback for detailed logging
        tb_str = ''.join(traceback.format_tb(error.__traceback__))
        
        # Log detailed error information
        self.logger.error(
            f"[{error_code_short}] {context}: {str(error)}\n"
            f"Type: {type(error).__name__}\n"
            f"Traceback: {tb_str}"
        )
        
        # Store error details for potential reporting
        self.error_codes[error_code] = {
            'error': str(error),
            'type': type(error).__name__,
            'context': context,
            'traceback': tb_str,
            'time': time.time()
        }
        
        # Update UI if requested
        if display_to_user and hasattr(self.app, 'status_label'):
            error_type = type(error).__name__
            message = f"Error [{error_code_short}]: {context} - {error_type}"
            try:
                self.app.status_label.config(text=message)
            except Exception:
                # Fallback if status label update fails
                pass
                
        # Get suggestion if available
        suggestion = self.get_suggestion(error)
        
        # Return the error code for reference
        return error_code_short, suggestion
        
    def get_suggestion(self, error):
        """Get a user-friendly suggestion based on error type."""
        error_type = type(error).__name__
        error_str = str(error).lower()
        
        suggestions = {
            'FileNotFoundError': "Please verify the file path exists and is accessible.",
            'PermissionError': "You don't have permission to access this file or directory. Try running as administrator.",
            'ValueError': "Invalid input value. Please check your input parameters.",
            'OSError': "Operating system error. Check file access and system resources.",
            'MemoryError': "Not enough memory. Close other applications and try again.",
            'TimeoutError': "Operation timed out. Check network connectivity or try again.",
            'IOError': "Input/output error. Verify disk space and file accessibility."
        }
        
        # Check for specific error patterns in the error message
        if "disk full" in error_str or "no space" in error_str:
            return "Your disk is full. Free up some space and try again."
        elif "access denied" in error_str:
            return "Access to the file or folder was denied. Check your permissions."
        elif "network" in error_str:
            return "Network error occurred. Check your connection and try again."
        
        # Return general suggestion based on error type
        return suggestions.get(error_type, "An error occurred. Please try again or contact support.")


class ThreadManager:
    """Manages thread safety for GUI updates and parallel processing."""
    
    def __init__(self, root=None):
        self.queue = Queue()
        self.lock = Lock()
        self.root = root
        self.active_threads = set()
        
    def safe_update(self, callback, *args):
        """Safely queue a UI update to be processed in the main thread."""
        with self.lock:
            self.queue.put((callback, args))
            
    def process_updates(self):
        """Process all queued UI updates."""
        while not self.queue.empty():
            try:
                callback, args = self.queue.get(block=False)
                callback(*args)
            except Exception as e:
                logging.error(f"Error processing queued update: {str(e)}")
            finally:
                self.queue.task_done()
                
    def start_thread(self, target, args=(), kwargs=None):
        """Start a new thread and track it."""
        if kwargs is None:
            kwargs = {}
            
        thread = threading.Thread(target=self._thread_wrapper, 
                                args=(target, args, kwargs))
        thread.daemon = True
        
        with self.lock:
            self.active_threads.add(thread)
            
        thread.start()
        return thread
        
    def _thread_wrapper(self, target, args, kwargs):
        """Wrapper to automatically remove completed threads from tracking."""
        try:
            return target(*args, **kwargs)
        except Exception as e:
            logging.error(f"Thread error: {str(e)}")
            traceback.print_exc()
        finally:
            with self.lock:
                for thread in self.active_threads:
                    if thread is threading.current_thread():
                        self.active_threads.remove(thread)
                        break
                        
    def stop_all_threads(self):
        """Set flags to stop all active threads."""
        with self.lock:
            active_count = len(self.active_threads)
            logging.info(f"Attempting to stop {active_count} active threads")
            
            # Note: This doesn't forcibly terminate threads, which is not possible in Python
            # Threads must cooperatively check for termination signals
            
            return active_count


# Constants
HASH_FILE_PATH = r"C:\Users\User\Documents\Discovery_Batch_3\Discovery_Batch3_Hash_Numbers.txt"
TARGET_FOLDER = r"E:\Batch_3\Original format\Discovery Batch 3"
SCRIPT_FOLDER = r"C:\Users\User\Documents\hash" 
QUARANTINE_FOLDER = r"C:\Users\User\Documents\hash\Removed_files"
FILE_NAMES_PATH = r"C:\Users\User\Documents\Bidvest_batch_1\File_Names_Bidvest_Batch_1(Non-Priviledged).txt"  # New constant for file names

# Configure logging
logging.basicConfig(
    filename='duplicate_report.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def load_hashes_from_file(file_path):
    try:
        # Sanitize and validate the file path
        safe_path = PathSanitizer.sanitize_path(file_path)
        
        # Check file size to prevent loading extremely large files
        file_size = os.path.getsize(safe_path)
        if file_size > 100 * 1024 * 1024:  # 100MB limit
            logging.warning(f"Hash file size exceeds recommended limit: {file_size} bytes")
            raise ValueError(f"Hash file too large: {file_size} bytes")
            
        with open(safe_path, 'r', encoding='utf-8', errors='replace') as file:
            lines = file.readlines()
            valid_hashes = set()
            invalid_hashes = []
            duplicates_count = 0
            seen_hashes = set()
            
            for line_num, line in enumerate(lines, 1):
                try:
                    # Debug
                    print(f"Original line: '{line}'")
                    
                    hash_value = line.strip()
                    print(f"Processed line: '{hash_value}'")
                    
                    # Skip empty lines or lines with only whitespace
                    if not hash_value:
                        continue
                    
                    # Normalize hash to lowercase for consistent comparison
                    lower_hash_value = hash_value.lower()
                    
                    # Validate hash format
                    if (re.fullmatch(r'[a-fA-F0-9]{32}', lower_hash_value) or  # MD5
                        re.fullmatch(r'[a-fA-F0-9]{40}', lower_hash_value) or  # SHA-1
                        re.fullmatch(r'[a-fA-F0-9]{64}', lower_hash_value) or  # SHA-256
                        re.fullmatch(r'[a-fA-F0-9]{128}', lower_hash_value)):  # SHA-512
                        if lower_hash_value in seen_hashes:
                            duplicates_count += 1
                            logging.debug(f"Duplicate hash found at line {line_num}: {lower_hash_value}")
                        else:
                            valid_hashes.add(lower_hash_value)
                            seen_hashes.add(lower_hash_value)
                    else:
                        invalid_hashes.append((line_num, hash_value))
                        logging.warning(f"Invalid hash format at line {line_num}: {hash_value}")
                except Exception as e:
                    logging.error(f"Error processing line {line_num} in hash file: {str(e)}")
                    invalid_hashes.append((line_num, f"{line.strip()} (Error: {str(e)})"))
            
            # Log statistics
            if invalid_hashes:
                invalid_count = len(invalid_hashes)
                logging.warning(f"{invalid_count} invalid hashes in {file_path}: " + 
                               f"First few: {', '.join(str(h[1]) for h in invalid_hashes[:5])}")
                               
            if duplicates_count > 0:
                logging.info(f"{duplicates_count} duplicate hashes were removed from {file_path}")
                
            logging.info(f"Successfully loaded {len(valid_hashes)} valid hashes from {file_path}")
            
            return valid_hashes, invalid_hashes, duplicates_count
            
    except UnicodeDecodeError as e:
        logging.error(f"Character encoding error in hash file {file_path}: {str(e)}")
        raise ValueError(f"Character encoding error in hash file. Try saving as UTF-8: {str(e)}")
    except Exception as e:
        logging.error(f"Error processing hash file {file_path}: {str(e)}")
        print(f"Debug: Error processing hash file {file_path}: {str(e)}")
        raise

def load_file_names_from_file(file_path):
    """Load file names from a text file with enhanced error handling and security."""
    print(f"Debug: Attempting to load file names from: {file_path}")
    
    # Sanitize and validate the file path
    try:
        safe_path = PathSanitizer.sanitize_path(file_path)
    except ValueError as e:
        logging.error(f"Invalid file path: {str(e)}")
        raise ValueError(f"Invalid file path: {str(e)}")
    
    # Check file size to prevent loading extremely large files
    try:
        file_size = os.path.getsize(safe_path)
        if file_size > 100 * 1024 * 1024:  # 100MB limit
            logging.warning(f"File names file size exceeds recommended limit: {file_size} bytes")
            raise ValueError(f"File names file too large: {file_size} bytes")
    except OSError as e:
        logging.error(f"Error checking file size: {str(e)}")
        raise
    
    # Try different encodings with enhanced security
    encodings = ['utf-8', 'latin1', 'cp1252', 'iso-8859-1', 'utf-16', 'utf-32']
    last_error = None
    duplicates = {}
    
    for encoding in encodings:
        try:
            print(f"Debug: Trying encoding: {encoding}")
            with open(safe_path, 'r', encoding=encoding, errors='replace') as file:
                # Read all lines and process each one
                file_names = set()
                line_count = 0
                skipped_lines = 0
                invalid_lines = []
                
                for line_num, line in enumerate(file, 1):
                    line_count += 1
                    try:
                        # Strip whitespace but preserve the exact file name
                        file_name = line.strip()
                        
                        if not file_name:  # Skip empty lines
                            skipped_lines += 1
                            continue
                            
                        # Remove any quotes if present (both single and double)
                        file_name = file_name.strip('"\'')
                        
                        # Handle Windows path separators
                        file_name = file_name.replace('\\', '/')
                        
                        # Validate file name - reject obviously invalid names
                        invalid_chars = ['<', '>', ':', '"', '|', '?', '*']
                        if any(char in file_name for char in invalid_chars):
                            invalid_lines.append((line_num, file_name))
                            logging.warning(f"Invalid file name at line {line_num}: {file_name}")
                            continue
                        
                        # Track duplicates by line number
                        if file_name in file_names:
                            if file_name not in duplicates:
                                duplicates[file_name] = []
                            duplicates[file_name].append(line_num)
                            logging.debug(f"Duplicate file name found at line {line_num}: {file_name}")
                        else:
                            file_names.add(file_name)
                        
                        print(f"Debug: Added file name: '{file_name}'")
                        
                    except Exception as e:
                        logging.error(f"Error processing line {line_num}: {str(e)}")
                        invalid_lines.append((line_num, f"{line.strip()} (Error: {str(e)})"))
                
                # Log success with this encoding
                print(f"Debug: Successfully loaded {len(file_names)} file names from {line_count} lines using {encoding} encoding")
                logging.info(f"Loaded {len(file_names)} file names from {line_count} lines in {file_path} using {encoding} encoding")
                
                # Log statistics
                if skipped_lines > 0:
                    print(f"Debug: Skipped {skipped_lines} empty lines")
                    logging.info(f"Skipped {skipped_lines} empty lines")
                    
                if invalid_lines:
                    print(f"Debug: Found {len(invalid_lines)} invalid file names")
                    logging.warning(f"Found {len(invalid_lines)} invalid file names")
                
                # Analyze file types for logging
                file_types = {}
                for name in file_names:
                    ext = os.path.splitext(name)[1].lower()
                    file_types[ext] = file_types.get(ext, 0) + 1
                print(f"Debug: File type distribution: {file_types}")
                logging.info(f"File type distribution: {file_types}")
                
                return file_names, duplicates, line_count, skipped_lines, invalid_lines
                
        except UnicodeDecodeError as e:
            print(f"Debug: {encoding} encoding failed: {str(e)}")
            last_error = e
            continue
        except Exception as e:
            print(f"Debug: Unexpected error with {encoding} encoding: {str(e)}")
            logging.error(f"Error loading file names from {file_path} with encoding {encoding}: {str(e)}")
            last_error = e
            continue
    
    # If we get here, none of the encodings worked
    error_msg = f"Could not read file with any of the supported encodings: {encodings}"
    if last_error:
        error_msg += f"\nLast error: {str(last_error)}"
    print(f"Debug: {error_msg}")
    logging.error(error_msg)
    raise ValueError(error_msg)

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

def normalize_long_path(path):
    """Convert a path to Windows extended-length format."""
    path_str = str(path)
    # Skip if already in extended format
    if path_str.startswith('\\\\?\\'):
        return path_str
    
    # Convert to absolute path and add extended-length prefix
    abs_path = os.path.abspath(path_str)
    return '\\\\?\\' + abs_path


def custom_walk(top):
    """
    A custom directory walker that supports long paths on Windows.
    Similar to os.walk but uses extended path syntax.
    """
    top = os.path.normpath(top)
    
    try:
        # Get all entries in the directory
        scandir_it = os.scandir(top)
    except OSError as error:
        logging.warning(f"Error accessing directory {top}: {error}")
        return
        
    with scandir_it:
        dirs = []
        files = []
        
        # Split directories and files
        for entry in scandir_it:
            try:
                is_dir = entry.is_dir()
                if is_dir:
                    dirs.append(entry.name)
                else:
                    files.append(entry.name)
            except OSError as error:
                logging.warning(f"Error accessing {entry.path}: {error}")
        
        # Yield the current level
        yield top, dirs, files
        
        # Recursively walk directories
        for dirname in dirs:
            new_path = os.path.join(top, dirname)
            # Use a try-except block to handle potential errors with specific directories
            try:
                yield from custom_walk(new_path)
            except OSError as error:
                logging.warning(f"Error walking directory {new_path}: {error}")


def check_path_length(path):
    """Warn about paths approaching length limits"""
    if len(str(path)) > 240:
        logging.warning(f"Path is approaching Windows MAX_PATH limit: {path}")


def count_files_safely(directory):
    """Count files with robust error handling"""
    count = 0
    try:
        for root, dirs, files in custom_walk(directory):
            count += len(files)
    except Exception as e:
        logging.error(f"Error counting files: {str(e)}")
    return count


def find_and_compare_hashes(directory, input_hashes, progress_bar, progress_bar_label, root, file_names=None, algorithms=None, update_progress_callback=None):
    """Core processing with thread-safe progress visualization and security enhancements."""
    if algorithms is None:
        algorithms = ['md5', 'sha1']
        
    # Create thread manager for safe UI updates
    thread_manager = ThreadManager(root)
    
    # Initialize data storage
    file_hashes = {}
    matches = []
    moved_files_info = []
    failed_moves = []
    failed_scans = []
    total_files_processed = 0
    
    # Create process lock for thread safety
    process_lock = Lock()

    # Initialize error handler
    error_handler = ErrorHandler(root)

    logging.info(f"Starting scan in directory: {directory}")
    logging.info(f"Using algorithms: {', '.join(algorithms)}")
    logging.info(f"Input hashes count: {len(input_hashes)}")
    if file_names:
        logging.info(f"File names to check: {len(file_names)}")
    
    print(f"Scanning directory: {directory} using algorithms: {', '.join(algorithms)}")
    
    try:
        # Validate and sanitize the directory path
        safe_directory = PathSanitizer.sanitize_path(directory)
        
        # Ensure directory exists
        if not os.path.isdir(safe_directory):
            raise ValueError(f"Invalid directory: {safe_directory}")
            
        # Ensure quarantine folder exists with error handling
        try:
            quarantine_folder = Path(QUARANTINE_FOLDER)
            quarantine_folder.mkdir(parents=True, exist_ok=True)
            logging.info(f"Quarantine folder ensured: {QUARANTINE_FOLDER}")
        except PermissionError as e:
            logging.error(f"Permission error creating quarantine folder: {str(e)}")
            raise ValueError(f"Cannot create quarantine folder: {str(e)}")
        except Exception as e:
            logging.error(f"Error creating quarantine folder: {str(e)}")
            raise ValueError(f"Cannot create quarantine folder: {str(e)}")

        # Get total file count for progress bar with enhanced error handling
        try:
            # Use a more efficient and safer file counting method
            total_files = count_files_safely(safe_directory)
            logging.info(f"Total files to process: {total_files}")
            
            # Update UI with file count
            def update_max_progress():
                progress_bar['maximum'] = total_files
                progress_bar_label.config(text=f"Found {total_files} files. Beginning processing...")
                
            root.after(0, update_max_progress)
            
        except Exception as e:
            error_code, suggestion = error_handler.handle(e, "Error counting files")
            logging.error(f"[{error_code}] Error counting files: {str(e)}")
            total_files = 0  # Set a default to avoid division by zero
            
            # Update UI with error
            def update_error_status():
                progress_bar_label.config(text=f"Error counting files. Proceeding anyway.")
                
            root.after(0, update_error_status)
        
        # Set up a thread-safe queue for processing results
        results_queue = Queue()
        
        # Monitor for user cancellation
        cancel_scan = threading.Event()
        
        # Create a list to hold all worker threads
        worker_threads = []
        
        # Function to safely update UI from worker threads
        def safe_update_progress(current, total, status=None):
            if update_progress_callback:
                update_progress_callback(current, total)
            else:
                def update_ui():
                    progress_bar['value'] = current
                    if status:
                        progress_bar_label.config(text=status)
                    else:
                        progress_percentage = (current / total) * 100 if total > 0 else 0
                        progress_bar_label.config(text=f"Progress: {progress_percentage:.2f}%")
                
                thread_manager.safe_update(root.after, 0, update_ui)
                
        # Process a single file safely
        def process_file(file_path):
            try:
                # Skip processing if cancellation requested
                if cancel_scan.is_set():
                    return None
                    
                # Check if file name matches first (faster than computing hashes)
                if file_names and file_path.name in file_names:
                    logging.info(f"File name match found: {file_path}")
                    
                    # Use thread-safe queue to report match
                    result = {
                        'type': 'name_match',
                        'file_path': file_path,
                        'hash': 'N/A',
                        'algorithm': 'File Name'
                    }
                    
                    # Attempt to move the file securely
                    try:
                        new_path, error = secure_move(file_path)
                        if new_path:
                            logging.info(f"Successfully moved file: {file_path} -> {new_path}")
                            result['new_path'] = new_path
                            result['moved'] = True
                        else:
                            logging.error(f"Failed to move file: {file_path} - {error}")
                            result['error'] = error
                            result['moved'] = False
                    except Exception as e:
                        logging.error(f"Exception moving file {file_path}: {str(e)}")
                        result['error'] = str(e)
                        result['moved'] = False
                        
                    return result
                
                # Compute file hashes with security and error handling
                try:
                    file_hashes_for_file = compute_hashes(file_path, algorithms)
                    logging.debug(f"Computed hashes for file: {file_path}")
                except Exception as e:
                    logging.error(f"Error computing hash for {file_path}: {str(e)}")
                    return {
                        'type': 'error',
                        'file_path': file_path,
                        'error': str(e)
                    }
                
                # Check for hash matches
                for algorithm, file_hash in file_hashes_for_file.items():
                    if file_hash in input_hashes:
                        logging.info(f"Hash match found: {file_path} using {algorithm}")
                        
                        # Create result object
                        result = {
                            'type': 'hash_match',
                            'file_path': file_path,
                            'hash': file_hash,
                            'algorithm': algorithm
                        }
                        
                        # Attempt secure move
                        try:
                            new_path, error = secure_move(file_path)
                            if new_path:
                                logging.info(f"Successfully moved matched file: {file_path} -> {new_path}")
                                result['new_path'] = new_path
                                result['moved'] = True
                            else:
                                logging.error(f"Failed to move matched file: {file_path} - {error}")
                                result['error'] = error
                                result['moved'] = False
                        except Exception as e:
                            logging.error(f"Exception moving matched file {file_path}: {str(e)}")
                            result['error'] = str(e)
                            result['moved'] = False
                            
                        return result
                        
                # No match found
                return None
                
            except Exception as e:
                logging.error(f"Unhandled error processing file {file_path}: {str(e)}")
                return {
                    'type': 'error',
                    'file_path': file_path,
                    'error': str(e)
                }
                
        # Worker function for processing files in a separate thread
        def worker_thread():
            while not cancel_scan.is_set() and files_to_process.qsize() > 0:
                try:
                    file_path = files_to_process.get(timeout=0.5)
                    result = process_file(file_path)
                    
                    if result:
                        # Put result in queue for main thread to process
                        results_queue.put(result)
                        
                    # Report progress
                    with process_lock:
                        nonlocal total_files_processed
                        total_files_processed += 1
                        
                    # Update progress safely
                    current_progress = total_files_processed
                    safe_update_progress(current_progress, total_files)
                    
                except Queue.Empty:
                    # No more files to process
                    break
                except Exception as e:
                    logging.error(f"Worker thread error: {str(e)}")
                    
                finally:
                    if not files_to_process.empty():
                        files_to_process.task_done()
        
        # Create a queue of files to process
        files_to_process = Queue()
        
        # Populate the queue with files
        for file_path in Path(safe_directory).rglob('*'):
            if file_path.is_file():
                try:
                    # Skip files in quarantine folder
                    if str(file_path).startswith(str(Path(QUARANTINE_FOLDER))):
                        continue
                        
                    files_to_process.put(file_path)
                except Exception as e:
                    logging.error(f"Error queueing file {file_path}: {str(e)}")
        
        # Calculate optimal number of worker threads based on CPU cores
        num_workers = min(os.cpu_count() or 4, 8)  # Use up to 8 threads max
        logging.info(f"Starting {num_workers} worker threads")
        
        # Start worker threads
        for _ in range(num_workers):
            thread = threading.Thread(target=worker_thread, daemon=True)
            thread.start()
            worker_threads.append(thread)
            
        # Monitor thread for processing results and updating UI
        def monitor_results():
            nonlocal matches, moved_files_info, failed_moves, failed_scans
            
            try:
                # Check if user requested cancellation
                if cancel_scan.is_set():
                    return
                
                # Process available results
                processed_results = 0
                while not results_queue.empty() and processed_results < 10:  # Process in batches
                    try:
                        result = results_queue.get(block=False)
                        processed_results += 1
                        
                        # Process based on result type
                        if result['type'] == 'hash_match' or result['type'] == 'name_match':
                            file_path = result['file_path']
                            file_hash = result['hash']
                            algorithm = result['algorithm']
                            
                            # Add to matches list
                            with process_lock:
                                matches.append((file_path, file_hash, algorithm))
                            
                            # Handle move result
                            if result.get('moved', False):
                                with process_lock:
                                    moved_files_info.append((file_path, result['new_path'], file_hash, algorithm))
                            elif 'error' in result:
                                with process_lock:
                                    failed_moves.append((file_path, file_hash, algorithm, result['error']))
                                    
                        elif result['type'] == 'error':
                            with process_lock:
                                failed_scans.append((result['file_path'], result['error']))
                                
                    except Queue.Empty:
                        break
                    finally:
                        results_queue.task_done()
                
                # Check if all worker threads have finished
                all_workers_done = all(not thread.is_alive() for thread in worker_threads)
                queue_empty = files_to_process.empty() and results_queue.empty()
                
                if all_workers_done and queue_empty:
                    # All processing complete, finalize
                    logging.info(f"All worker threads complete. Finalizing results.")
                    finalize_results()
                else:
                    # Schedule next check
                    root.after(100, monitor_results)
                    
            except Exception as e:
                logging.error(f"Error in monitor thread: {str(e)}")
                # Schedule next check even after error
                root.after(100, monitor_results)
        
        # Function to finalize and report results
        def finalize_results():
            logging.info(f"Scan completed. Total files processed: {total_files_processed}")
            logging.info(f"Matches found: {len(matches)}")
            logging.info(f"Files moved: {len(moved_files_info)}")
            logging.info(f"Failed moves: {len(failed_moves)}")
            logging.info(f"Failed scans: {len(failed_scans)}")
            
            # Generate report with original formatting
            try:
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
                        report_file.write(f"Hash ({algorithm.upper()}: {file_hash}\n\n")
                    
                    report_file.write("\nFailed Moves:\n")
                    report_file.write("====================\n")
                    for file_path, file_hash, algorithm, error in failed_moves:
                        report_file.write(f"File: {file_path}, Hash: {file_hash}, Algorithm: {algorithm}\n")
                        report_file.write(f"Error: {error}\n\n")

                    report_file.write("\nFailed Scans:\n")
                    report_file.write("====================\n")
                    for file_path, error in failed_scans:
                        report_file.write(f"File: {file_path}, Error: {error}\n")
                
                logging.info("Report file generated: matches_report.txt")
            except Exception as e:
                logging.error(f"Error generating report file: {str(e)}")
            
            # Display removed files folder
            try:
                os.startfile(QUARANTINE_FOLDER)
                logging.info(f"Opened quarantine folder: {QUARANTINE_FOLDER}")
            except Exception as e:
                logging.warning(f"Could not open quarantine folder: {str(e)}")

            # Open generated report
            try:
                os.startfile('matches_report.txt')
                logging.info("Opened matches report file")
            except Exception as e:
                logging.warning(f"Could not open report file: {str(e)}")
        
        # Start monitoring thread
        monitor_results()
        
        # Wait for completion (handled by monitor_results)
        return matches, moved_files_info, failed_moves, failed_scans, total_files_processed
        
    except Exception as e:
        error_code, suggestion = error_handler.handle(e, "Error during scan")
        logging.error(f"[{error_code}] Scan failed: {str(e)}")
        # Ensure UI is updated with error
        def update_error_status():
            progress_bar_label.config(text=f"Error [{error_code}]: {str(e)}")
            
        root.after(0, update_error_status)
        return [], [], [], [(str(e), "Scan initialization error")], 0

def secure_move(file_path):
    """
    Move file to quarantine with enhanced security, permission checking, and conflict resolution.
    
    Args:
        file_path: Path object or string path of file to move
        
    Returns:
        (Path object of new location, None) on success or
        (None, error message) on failure
    """
    try:
        # Validate input path
        safe_file_path = PathSanitizer.sanitize_path(file_path)
        
        # Ensure source file exists
        if not safe_file_path.exists():
            error_msg = f"Source file does not exist: {safe_file_path}"
            logging.error(error_msg)
            return None, error_msg
            
        # Validate quarantine folder path
        safe_dest_folder = PathSanitizer.sanitize_path(QUARANTINE_FOLDER)
        
        # Create the destination folder if it doesn't exist
        try:
            os.makedirs(safe_dest_folder, exist_ok=True)
        except PermissionError:
            error_msg = f"Permission denied creating quarantine folder: {safe_dest_folder}"
            logging.error(error_msg)
            return None, error_msg
        except OSError as e:
            error_msg = f"Error creating quarantine folder: {str(e)}"
            logging.error(error_msg)
            return None, error_msg
        
        # Get the filename and prevent path traversal in filenames
        file_name = os.path.basename(safe_file_path)
        
        # Skip invalid filenames
        if not file_name or file_name in ('.', '..') or '/' in file_name or '\\' in file_name:
            error_msg = f"Invalid filename: {file_name}"
            logging.error(error_msg)
            return None, error_msg
            
        # Create the destination path
        dest_path = os.path.join(safe_dest_folder, file_name)
        
        # Handle filename conflicts with more sophisticated naming
        attempt = 1
        while os.path.exists(dest_path):
            base_name, extension = os.path.splitext(file_name)
            # Create a unique name based on timestamp and attempt number
            timestamp = int(time.time())
            new_name = f"{base_name}_conflict_{timestamp}_{attempt}{extension}"
            dest_path = os.path.join(safe_dest_folder, new_name)
            attempt += 1
            
            # Prevent infinite loops
            if attempt > 100:
                error_msg = "Failed to create unique filename after 100 attempts"
                logging.error(error_msg)
                return None, error_msg
        
        # Check file permissions on source and destination
        try:
            # Test file access without actually opening
            os.access(safe_file_path, os.R_OK)
            
            # Ensure destination is writable
            os.access(os.path.dirname(dest_path), os.W_OK)
        except PermissionError as e:
            error_msg = f"Permission check failed: {str(e)}"
            logging.error(error_msg)
            return None, error_msg
            
        # Perform the move operation with robust error handling
        try:
            # First try atomic move
            shutil.move(safe_file_path, dest_path)
        except (shutil.Error, PermissionError) as e:
            logging.warning(f"Direct move failed, attempting copy+delete: {str(e)}")
            
            # Fall back to copy and delete
            try:
                shutil.copy2(safe_file_path, dest_path)
                
                # Verify the copy was successful
                if not os.path.exists(dest_path):
                    error_msg = "File copy succeeded but destination file not found"
                    logging.error(error_msg)
                    return None, error_msg
                    
                if os.path.getsize(dest_path) != os.path.getsize(safe_file_path):
                    error_msg = "File size mismatch after copy"
                    logging.error(error_msg)
                    # Clean up partial copy
                    try:
                        os.remove(dest_path)
                    except:
                        pass
                    return None, error_msg
                
                # Try to delete the original
                try:
                    os.remove(safe_file_path)
                except Exception as del_err:
                    logging.warning(f"Original file could not be deleted: {str(del_err)}")
                    # Continue anyway - at least we have a copy
            except Exception as copy_err:
                error_msg = f"Copy operation failed: {str(copy_err)}"
                logging.error(error_msg)
                return None, error_msg
                
        # Apply appropriate permissions to the moved file
        try:
            set_windows_permissions(dest_path)
        except Exception as perm_err:
            logging.warning(f"Could not set permissions on moved file: {str(perm_err)}")
            # Continue anyway - file was successfully moved
        
        logging.info(f"Successfully moved file from {safe_file_path} to {dest_path}")
        return Path(dest_path), None
        
    except Exception as e:
        error_msg = f"Unexpected error in secure_move: {str(e)}"
        logging.error(error_msg)
        return None, error_msg

def compute_hashes(file_path, algorithms=None):
    """Compute hashes for a file using specified algorithms and secure buffered reading."""
    if algorithms is None:
        algorithms = ['md5', 'sha1']
    
    try:
        # Use the secure file handler for hash computation
        return SecureFileHandler.compute_hashes(file_path, algorithms)
    except (FileNotFoundError, PermissionError, ValueError, IOError) as e:
        # Log specific error and re-raise
        logging.error(f"Error computing hashes for {file_path}: {str(e)}")
        raise
    except Exception as e:
        # Log unexpected errors
        logging.error(f"Unexpected error computing hashes for {file_path}: {str(e)}")
        raise ValueError(f"Error computing file hash: {str(e)}")

def find_and_compare_hashes(directory, input_hashes, progress_bar, progress_bar_label, root, file_names=None, algorithms=['md5', 'sha1'], update_progress_callback=None):
    """Core processing with progress visualization"""
    file_hashes = {}
    matches = []
    moved_files_info = []
    failed_moves = []
    failed_scans = []
    total_files_processed = 0

    logging.info(f"Starting scan in directory: {directory}")
    logging.info(f"Using algorithms: {', '.join(algorithms)}")
    logging.info(f"Input hashes count: {len(input_hashes)}")
    if file_names:
        logging.info(f"File names to check: {len(file_names)}")
    
    print(f"Scanning directory: {directory} using algorithms: {', '.join(algorithms)}")
    
    # Ensure quarantine folder exists
    Path(QUARANTINE_FOLDER).mkdir(parents=True, exist_ok=True)
    logging.info(f"Quarantine folder ensured: {QUARANTINE_FOLDER}")

    # Get total file count for progress bar
    total_files = sum(1 for _ in Path(directory).rglob('*') if _.is_file())
    logging.info(f"Total files to process: {total_files}")
    
    # Set the maximum value for the progress bar
    progress_bar['maximum'] = total_files

    for file_path in Path(directory).rglob('*'):
        if file_path.is_file():
            total_files_processed += 1
            
            # Update progress through callback if provided
            if update_progress_callback:
                update_progress_callback(total_files_processed, total_files)
            else:
                # Fallback to direct progress bar update
                progress_bar['value'] = total_files_processed
                progress_percentage = (total_files_processed / total_files) * 100
                root.after(0, lambda: progress_bar_label.config(text=f"Progress: {progress_percentage:.2f}%"))
            
            try:
                # Check if file name matches
                if file_names and file_path.name in file_names:
                    logging.info(f"File name match found: {file_path}")
                    matches.append((file_path, 'N/A', 'File Name'))
                    new_path, error = secure_move(file_path)
                    if new_path:
                        logging.info(f"Successfully moved file: {file_path} -> {new_path}")
                        moved_files_info.append((file_path, new_path, 'N/A', 'File Name'))
                    else:
                        logging.error(f"Failed to move file: {file_path} - {error}")
                        failed_moves.append((file_path, 'N/A', 'File Name', error))
                    continue

                file_hashes_for_file = compute_hashes(file_path, algorithms)
                logging.debug(f"Computed hashes for file: {file_path}")

                for algorithm, file_hash in file_hashes_for_file.items():
                    logging.debug(f"Checking hash for {file_path} using {algorithm}: {file_hash}")

                    if file_hash in input_hashes:
                        logging.info(f"Hash match found: {file_path} using {algorithm}")
                        print(f"Match found: {file_path} using {algorithm}")
                        matches.append((file_path, file_hash, algorithm))

                        # Attempt secure move
                        new_path, error = secure_move(file_path)
                        if new_path:
                            logging.info(f"Successfully moved matched file: {file_path} -> {new_path}")
                            moved_files_info.append((file_path, new_path, file_hash, algorithm))
                            print(f"Moved file: {file_path} -> {new_path}")
                        else:
                            logging.error(f"Failed to move matched file: {file_path} - {error}")
                            failed_moves.append((file_path, file_hash, algorithm, error))
                            print(f"Failed to move: {file_path} - {error}")

                if file_hash not in file_hashes:
                    file_hashes[file_hash] = file_path
                    logging.debug(f"Added file to hash list: {file_path} with hash {file_hash}")
                        
            except Exception as e:
                logging.error(f"Error processing file {file_path}: {e}")
                print(f"Error processing file {file_path}: {e}")
                failed_scans.append((file_path, str(e)))

    # Log final statistics
    logging.info(f"Scan completed. Total files processed: {total_files_processed}")
    logging.info(f"Matches found: {len(matches)}")
    logging.info(f"Files moved: {len(moved_files_info)}")
    logging.info(f"Failed moves: {len(failed_moves)}")
    logging.info(f"Failed scans: {len(failed_scans)}")

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
            report_file.write(f"Hash ({algorithm.upper()}: {file_hash}\n\n")
        
        report_file.write("\nFailed Moves:\n")
        report_file.write("====================\n")
        for file_path, file_hash, algorithm, error in failed_moves:
            report_file.write(f"File: {file_path}, Hash: {file_hash}, Algorithm: {algorithm}\n")
            report_file.write(f"Error: {error}\n\n")

        report_file.write("\nFailed Scans:\n")
        report_file.write("====================\n")
        for file_path, error in failed_scans:
            report_file.write(f"File: {file_path}, Error: {error}\n")

    logging.info("Report file generated: matches_report.txt")
    print(f"Scan complete. {len(moved_files_info)} files moved to quarantine.")
    print("Hashes of moved files:")
    for orig_path, new_path, file_hash, algorithm in moved_files_info:
        print(f"Original: {orig_path} | New: {new_path} | {algorithm.upper()}: {file_hash}")

    # Display removed files folder
    os.startfile(QUARANTINE_FOLDER)
    logging.info(f"Opened quarantine folder: {QUARANTINE_FOLDER}")

    # Open generated report
    os.startfile('matches_report.txt')
    logging.info("Opened matches report file")

    return matches, moved_files_info, failed_moves, failed_scans, total_files_processed

class HashVettingApp:

    def __init__(self, root):
        self.root = root
        self.root.title("OPTIMUS-VET")
        
        # Set up logging for the application
        self.setup_logging()
        
        # Initialize thread manager for thread safety
        self.thread_manager = ThreadManager(root)
        
        # Initialize error handler for centralized error management
        self.error_handler = ErrorHandler(self)
        
        # Initialize data storage attributes
        self.input_hashes = set()
        self.file_names = set()
        self.matches = []
        self.moved_files_info = []
        self.failed_moves = []
        self.failed_scans = []
        self.scan_start_time = None
        self.scan_end_time = None
        self.total_files_processed = 0
        self.total_files_matched = 0
        self.total_files_moved = 0
        self.total_errors = 0
        
        # Define color schemes
        self.dark_scheme = {
            'bg': '#2e2e2e',
            'fg': '#ffffff',
            'entry_bg': '#3e3e3e',
            'button_bg': '#4e4e4e',
            'frame_bg': '#2e2e2e',
            'border': '#6e6e6e'
        }
        
        self.light_scheme = {
            'bg': '#ffffff',
            'fg': '#000000',
            'entry_bg': '#f0f0f0',
            'button_bg': '#e0e0e0',
            'frame_bg': '#ffffff',
            'border': '#cccccc'
        }
        
        # Initialize with dark mode
        self.is_dark_mode = True

        # Configure grid weights for the root
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Main frame with increased outer padding and thicker, lighter border
        self.main_frame = tk.Frame(root, bg=self.dark_scheme['frame_bg'], 
                                 highlightbackground=self.dark_scheme['border'], 
                                 highlightthickness=4)
        self.main_frame.grid(row=0, column=0, padx=10, pady=10, sticky='nsew')

        # Configure row weights for better vertical distribution
        # The key is to give more weight to text areas and less to basic inputs
        row_weights = [1, 1, 1, 1, 4,  # Header buttons, input fields, preview label
                       1, 1, 1, 2, 1,  # Source/dest folder inputs, button frame, scan button, progress
                       1, 1, 3, 1, 3]  # Progress label, status, invalid hashes, duplicates label, duplicates
        
        # Apply weights to rows
        for i, weight in enumerate(row_weights):
            self.main_frame.grid_rowconfigure(i, weight=weight)
        
        # Configure column weights - give more weight to the middle column
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=3)  # Middle column gets more space
        self.main_frame.grid_columnconfigure(2, weight=1)

        # Create all UI elements
        self.create_ui_elements()

        # Enable drag and drop functionality after UI elements are created
        self.enable_drag_and_drop()

        # Apply color scheme after all UI elements are created
        self.apply_color_scheme(self.dark_scheme)

        # Add time tracking variables
        self.start_time = 0
        self.last_update_time = 0
        self.processing_rate = 0  # files per second
        
        # Define error suggestions
        self.error_suggestions = {
            "No such file or directory": "Please check if the file path is correct and the file exists.",
            "Permission denied": "Ensure you have the necessary permissions to access the file or folder.",
            "File is open in another program": "Close the file in other programs before proceeding.",
            "Invalid hash format": "Check if the hash values in the file are in the correct format (MD5, SHA-1, SHA-256, or SHA-512).",
            "Empty file": "The file appears to be empty. Please ensure the file contains valid data.",
            "Invalid file path": "The file path contains invalid characters or is too long. Try using a shorter path.",
            "Disk full": "There is not enough disk space to complete the operation. Free up some space and try again.",
            "File too large": "The file is too large to process. Consider splitting it into smaller files.",
            "Network error": "There was a problem accessing the network location. Check your connection and try again.",
            "Access denied": "You don't have permission to access this location. Try running the program as administrator.",
            "Path not found": "The specified path does not exist. Please verify the path and try again.",
            "Invalid folder": "The selected folder is not valid. Please choose a different folder.",
            "File in use": "The file is currently in use by another process. Close other applications and try again.",
            "Invalid file type": "The file type is not supported. Please use a text file (.txt) for hash or file name lists.",
            "Duplicate entries": "The file contains duplicate entries. Consider removing duplicates before proceeding.",
            "Corrupted file": "The file appears to be corrupted. Try using a backup or recreating the file.",
            "Timeout": "The operation timed out. Try again with a smaller dataset or check your system resources.",
            "Memory error": "Not enough memory available. Close other applications and try again.",
            "Invalid input": "The input data is not in the expected format. Please check the file contents.",
            "Missing data": "Required data is missing. Please ensure all necessary files are selected.",
            "Scan interrupted": "The scan was interrupted. You can start a new scan when ready.",
            "Invalid hash length": "The hash values have incorrect lengths. Verify the hash format.",
            "File locked": "The file is locked by another process. Close other applications and try again.",
            "Invalid characters": "The file contains invalid characters. Remove special characters and try again.",
            "Path too long": "The file path is too long. Consider moving the file to a shorter path.",
            "Invalid drive": "The specified drive is not available. Check if the drive is connected.",
            "Read-only file": "The file is read-only. Check file permissions and try again.",
            "Invalid file encoding": "The file has an unsupported encoding. Save it as UTF-8 and try again."
        }
        
        # Flag to track scan cancellation requests
        self.cancel_scan_requested = False
        
    def setup_logging(self):
        """Set up enhanced logging for the application"""
        try:
            # Check if we can write to the log file
            log_path = 'optimus_vet.log'
            
            # Set up the application logger with rotation
            handler = logging.handlers.RotatingFileHandler(
                log_path, maxBytes=5*1024*1024, backupCount=3)
                
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S')
                
            handler.setFormatter(formatter)
            
            # Create a specific logger for the application
            self.logger = logging.getLogger('optimus_vet')
            self.logger.setLevel(logging.INFO)
            
            # Remove existing handlers
            for hdlr in self.logger.handlers[:]:
                self.logger.removeHandler(hdlr)
        except Exception as e:
            logging.error(f"Error setting up logging: {str(e)}")

    def create_ui_elements(self):
        """Create all UI elements."""
        # Use a simple grid layout for all elements
        # This ensures everything is visible and properly spaced
        
        # Add theme toggle button at the top with more rounded corners
        self.theme_button = tk.Button(self.main_frame, 
                                    text="🌙 Dark Mode", 
                                    command=self.toggle_dark_mode,
                                    bg=self.dark_scheme['button_bg'],
                                    fg=self.dark_scheme['fg'],
                                    bd=0,
                                    relief='flat',
                                    height=1)
        self.theme_button.grid(row=0, column=0, sticky='ew', padx=5, pady=5)
        self.round_button(self.theme_button, 15)

        # Add help button in column 1
        self.help_button = tk.Button(self.main_frame, 
                                   text="❓ Help", 
                                   command=self.show_help,
                                   bg=self.dark_scheme['button_bg'],
                                   fg=self.dark_scheme['fg'],
                                   bd=0,
                                   relief='flat',
                                   height=1)
        self.help_button.grid(row=0, column=1, sticky='ew', padx=5, pady=5)
        self.round_button(self.help_button, 15)
        
        # Add tutorial button next to theme button
        self.tutorial_button = tk.Button(self.main_frame, 
                                       text="📚 Tutorial", 
                                       command=self.show_tutorial,
                                       bg=self.dark_scheme['button_bg'],
                                       fg=self.dark_scheme['fg'],
                                       bd=0,
                                       relief='flat',
                                       height=1)
        self.tutorial_button.grid(row=0, column=2, sticky='ew', padx=2)
        self.round_button(self.tutorial_button, 15)
        
        # Hash file input row
        self.hash_file_label = tk.Label(self.main_frame, 
                                      text="Hash File:", 
                                      bg=self.dark_scheme['frame_bg'], 
                                      fg=self.dark_scheme['fg'], 
                                      bd=2, 
                                      relief='groove')
        self.hash_file_label.grid(row=1, column=0, sticky='ew', padx=5, pady=5)
        self.round_label(self.hash_file_label, 15)
        
        self.hash_file_entry = tk.Entry(self.main_frame, 
                                      bg=self.dark_scheme['entry_bg'], 
                                      fg=self.dark_scheme['fg'], 
                                      insertbackground=self.dark_scheme['fg'],
                                      bd=2, 
                                      relief='groove')
        self.hash_file_entry.grid(row=1, column=1, sticky='ew', padx=5, pady=5)
        self.round_entry(self.hash_file_entry, 15)
        
        self.browse_hash_button = tk.Button(self.main_frame, 
                                          text="Browse", 
                                          command=self.browse_hash_file, 
                                          bg=self.dark_scheme['button_bg'], 
                                          fg=self.dark_scheme['fg'], 
                                          bd=0, 
                                          relief='flat', 
                                          height=1)
        self.browse_hash_button.grid(row=1, column=2, sticky='ew', padx=5, pady=5)
        self.round_button(self.browse_hash_button, 15)
        
        # File names input row
        self.file_names_label = tk.Label(self.main_frame, text="File Names File:", bg=self.dark_scheme['frame_bg'], fg=self.dark_scheme['fg'], bd=2, relief='groove')
        self.file_names_label.grid(row=2, column=0, sticky='ew', padx=5, pady=5)
        self.round_label(self.file_names_label, 15)
        
        self.file_names_entry = tk.Entry(self.main_frame, bg=self.dark_scheme['entry_bg'], fg=self.dark_scheme['fg'], insertbackground=self.dark_scheme['fg'], bd=2, relief='groove')
        self.file_names_entry.grid(row=2, column=1, sticky='ew', padx=5, pady=5)
        self.round_entry(self.file_names_entry, 15)
        
        self.browse_file_names_button = tk.Button(self.main_frame, text="Browse", command=self.browse_file_names_file, bg=self.dark_scheme['button_bg'], fg=self.dark_scheme['fg'], bd=0, relief='flat', height=1)
        self.browse_file_names_button.grid(row=2, column=2, sticky='ew', padx=5, pady=5)
        self.round_button(self.browse_file_names_button, 15)
        
        # Preview panel label
        self.preview_label = tk.Label(self.main_frame, text="File Preview:", bg=self.dark_scheme['frame_bg'], fg=self.dark_scheme['fg'], bd=2, relief='groove')
        self.preview_label.grid(row=3, column=0, columnspan=3, sticky='ew', padx=5, pady=5)
        self.round_label(self.preview_label, 15)

        # Preview panel with scrollbar for better usability
        preview_frame = tk.Frame(self.main_frame, bg=self.dark_scheme['frame_bg'])
        preview_frame.grid(row=4, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        preview_frame.grid_rowconfigure(0, weight=1)
        preview_frame.grid_columnconfigure(0, weight=1)
        
        preview_scrollbar = tk.Scrollbar(preview_frame)
        preview_scrollbar.grid(row=0, column=1, sticky='ns')
        
        self.preview_panel = tk.Text(preview_frame, height=6, bg=self.dark_scheme['entry_bg'], fg=self.dark_scheme['fg'], wrap='word', bd=2, relief='groove', yscrollcommand=preview_scrollbar.set)
        self.preview_panel.grid(row=0, column=0, sticky='nsew')
        preview_scrollbar.config(command=self.preview_panel.yview)
        self.round_text(self.preview_panel, 15)
        
        # Target folder row
        self.target_folder_label = tk.Label(self.main_frame, text="Source Folder:", bg=self.dark_scheme['frame_bg'], fg=self.dark_scheme['fg'], bd=2, relief='groove')
        self.target_folder_label.grid(row=5, column=0, sticky='ew', padx=5, pady=5)
        self.round_label(self.target_folder_label, 15)
        
        self.target_folder_entry = tk.Entry(self.main_frame, bg=self.dark_scheme['entry_bg'], fg=self.dark_scheme['fg'], insertbackground=self.dark_scheme['fg'], bd=2, relief='groove')
        self.target_folder_entry.grid(row=5, column=1, sticky='ew', padx=5, pady=5)
        self.round_entry(self.target_folder_entry, 15)
        
        self.browse_target_button = tk.Button(self.main_frame, text="Browse", command=self.browse_target_folder, bg=self.dark_scheme['button_bg'], fg=self.dark_scheme['fg'], bd=0, relief='flat', height=1)
        self.browse_target_button.grid(row=5, column=2, sticky='ew', padx=5, pady=5)
        self.round_button(self.browse_target_button, 15)
        
        # Quarantine folder row
        self.quarantine_folder_label = tk.Label(self.main_frame, text="Destination Folder:", bg=self.dark_scheme['frame_bg'], fg=self.dark_scheme['fg'], bd=2, relief='groove')
        self.quarantine_folder_label.grid(row=6, column=0, sticky='ew', padx=5, pady=5)
        self.round_label(self.quarantine_folder_label, 15)
        
        self.quarantine_folder_entry = tk.Entry(self.main_frame, bg=self.dark_scheme['entry_bg'], fg=self.dark_scheme['fg'], insertbackground=self.dark_scheme['fg'], bd=2, relief='groove')
        self.quarantine_folder_entry.grid(row=6, column=1, sticky='ew', padx=5, pady=5)
        self.round_entry(self.quarantine_folder_entry, 15)
        
        self.browse_quarantine_button = tk.Button(self.main_frame, text="Browse", command=self.browse_quarantine_folder, bg=self.dark_scheme['button_bg'], fg=self.dark_scheme['fg'], bd=0, relief='flat', height=1)
        self.browse_quarantine_button.grid(row=6, column=2, sticky='ew', padx=5, pady=5)
        self.round_button(self.browse_quarantine_button, 15)
        
        # Action buttons frame
        self.button_frame = tk.Frame(self.main_frame, bg=self.dark_scheme['frame_bg'])
        self.button_frame.grid(row=7, column=0, columnspan=3, sticky='ew', padx=5, pady=5)
        
        # Configure button frame for equal button sizes
        for i in range(5):  # Five buttons now (added cancel)
            self.button_frame.grid_columnconfigure(i, weight=1)
        
        # Load button
        self.load_button = tk.Button(self.button_frame, 
                                    text="Load Hashes", 
                                    command=self.load_data, 
                                    bg=self.dark_scheme['button_bg'], 
                                    fg=self.dark_scheme['fg'], 
                                    bd=0, 
                                    relief='flat', 
                                    height=1)
        self.load_button.grid(row=0, column=0, sticky='ew', padx=2, pady=2)
        self.round_button(self.load_button, 15)
        
        # Refresh data button
        self.refresh_data_button = tk.Button(self.button_frame, 
                                           text="Refresh Files", 
                                           command=self.refresh_data, 
                                           bg=self.dark_scheme['button_bg'], 
                                           fg=self.dark_scheme['fg'], 
                                           bd=0, 
                                           relief='flat', 
                                           height=1)
        self.refresh_data_button.grid(row=0, column=1, sticky='ew', padx=2, pady=2)
        self.round_button(self.refresh_data_button, 15)
        
        # Refresh GUI button
        self.refresh_gui_button = tk.Button(self.button_frame, 
                                          text="Refresh UI", 
                                          command=self.refresh_app, 
                                          bg=self.dark_scheme['button_bg'], 
                                          fg=self.dark_scheme['fg'], 
                                          bd=0, 
                                          relief='flat', 
                                          height=1)
        self.refresh_gui_button.grid(row=0, column=2, sticky='ew', padx=2, pady=2)
        self.round_button(self.refresh_gui_button, 15)
        
        # Cancel button - initially disabled
        self.cancel_button = tk.Button(self.button_frame, 
                                     text="Cancel Scan", 
                                     command=self.cancel_scan, 
                                     bg=self.dark_scheme['button_bg'], 
                                     fg=self.dark_scheme['fg'], 
                                     bd=0, 
                                     relief='flat', 
                                     height=1,
                                     state='disabled')
        self.cancel_button.grid(row=0, column=3, sticky='ew', padx=2, pady=2)
        self.round_button(self.cancel_button, 15)
        
        # Reports button
        self.reports_button = tk.Button(self.button_frame, 
                                      text="📊 Reports", 
                                      command=self.show_reports_menu, 
                                      bg=self.dark_scheme['button_bg'], 
                                      fg=self.dark_scheme['fg'], 
                                      bd=0, 
                                      relief='flat', 
                                      height=1)
        self.reports_button.grid(row=0, column=4, sticky='ew', padx=2, pady=2)
        self.round_button(self.reports_button, 15)
        
        # Add thread control variables
        self.scan_thread = None
        self.is_scanning = False
        
        # Style for the progress bar to make it more rounded
        style = ttk.Style()
        style.configure("Rounded.Horizontal.TProgressbar", 
                      thickness=20, 
                      borderwidth=0,
                      background=self.dark_scheme['button_bg'],
                      troughcolor=self.dark_scheme['entry_bg'])
        
        # Scan button - make it more prominent
        self.scan_button = tk.Button(self.main_frame, 
                                   text="Scan and Move", 
                                   bg=self.dark_scheme['button_bg'], 
                                   fg=self.dark_scheme['fg'], 
                                   height=2,  # Increase height for prominence 
                                   command=self.scan_and_move_threaded, 
                                   bd=0, 
                                   relief='flat', 
                                   padx=10, 
                                   pady=5)
        self.scan_button.grid(row=8, column=0, columnspan=3, sticky='ew', padx=5, pady=10)
        self.round_button(self.scan_button, 20)  # Extra rounded for primary action
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(self.main_frame, 
                                          orient='horizontal',
                                          mode='determinate',
                                          style="Rounded.Horizontal.TProgressbar")
        self.progress_bar.grid(row=9, column=0, columnspan=3, sticky='ew', padx=5, pady=5)
        
        # Progress label
        self.progress_bar_label = tk.Label(self.main_frame, 
                                         text="Ready", 
                                         bg=self.dark_scheme['frame_bg'], 
                                         fg=self.dark_scheme['fg'], 
                                         bd=2, 
                                         relief='groove')
        self.progress_bar_label.grid(row=10, column=0, columnspan=3, sticky='ew', padx=5, pady=5)
        self.round_label(self.progress_bar_label, 15)
        
        # Status label
        self.status_label = tk.Label(self.main_frame, text="Status: Idle", bg=self.dark_scheme['frame_bg'], fg=self.dark_scheme['fg'], bd=2, relief='groove', wraplength=400)
        self.status_label.grid(row=11, column=0, columnspan=3, sticky='ew', padx=5, pady=5)
        self.round_label(self.status_label, 15)
        
        # Invalid hashes text area with scrollbar
        invalid_frame = tk.Frame(self.main_frame, bg=self.dark_scheme['frame_bg'])
        invalid_frame.grid(row=12, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        invalid_frame.grid_rowconfigure(0, weight=1)
        invalid_frame.grid_columnconfigure(0, weight=1)
        
        invalid_scrollbar = tk.Scrollbar(invalid_frame)
        invalid_scrollbar.grid(row=0, column=1, sticky='ns')
        
        self.invalid_hashes_text = tk.Text(invalid_frame, height=5, bg=self.dark_scheme['entry_bg'], fg=self.dark_scheme['fg'], wrap='word', yscrollcommand=invalid_scrollbar.set)
        self.invalid_hashes_text.grid(row=0, column=0, sticky='nsew')
        invalid_scrollbar.config(command=self.invalid_hashes_text.yview)
        self.round_text(self.invalid_hashes_text, 15)
        
        # Duplicates label
        self.duplicates_label = tk.Label(self.main_frame, text="Duplicate File Names:", bg=self.dark_scheme['frame_bg'], fg=self.dark_scheme['fg'], bd=2, relief='groove')
        self.duplicates_label.grid(row=13, column=0, columnspan=3, sticky='ew', padx=5, pady=5)
        self.round_label(self.duplicates_label, 15)
        
        # Duplicates text area with scrollbar
        duplicates_frame = tk.Frame(self.main_frame, bg=self.dark_scheme['frame_bg'])
        duplicates_frame.grid(row=14, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        duplicates_frame.grid_rowconfigure(0, weight=1)
        duplicates_frame.grid_columnconfigure(0, weight=1)
        
        duplicates_scrollbar = tk.Scrollbar(duplicates_frame)
        duplicates_scrollbar.grid(row=0, column=1, sticky='ns')
        
        self.duplicates_text = tk.Text(duplicates_frame, height=5, bg=self.dark_scheme['entry_bg'], fg=self.dark_scheme['fg'], wrap='word', yscrollcommand=duplicates_scrollbar.set)
        self.duplicates_text.grid(row=0, column=0, sticky='nsew')
        duplicates_scrollbar.config(command=self.duplicates_text.yview)
        self.round_text(self.duplicates_text, 15)
    
    def load_data(self):
        """Load hashes from hash file with enhanced error handling."""
        # Clear existing data
        self.input_hashes = set()
        self.file_names = set() # Also clear file names when loading
        # Remove the non-existent method call
        # self.invalidate_status()
        
        hash_file_path = self.hash_file_entry.get()
        file_names_path = self.file_names_entry.get() 

        # Reset status label
        self.status_label.config(text="Loading...")
        self.root.update_idletasks() # Ensure label update is visible

        loaded_hashes = False
        loaded_names = False
        error_occurred = False
        
        # Handle hash file loading
        if hash_file_path:
            if os.path.isfile(hash_file_path):
                try:
                    self.input_hashes, invalid_hashes, duplicates_count = load_hashes_from_file(hash_file_path)
                    loaded_hashes = True
                    # Update invalid hashes display if needed
                    if invalid_hashes:
                        self.invalid_hashes_text.delete('1.0', tk.END)
                        self.invalid_hashes_text.insert(tk.END, f"Invalid/Unsupported Hashes Found:\n{', '.join(invalid_hashes)}")
                    else:
                        self.invalid_hashes_text.delete('1.0', tk.END)
                except Exception as e:
                    self.handle_error(f"Error loading hashes: {str(e)} ({hash_file_path})", "Invalid hash file")
                    error_occurred = True
            else:
                self.handle_error(f"Hash file not found: {hash_file_path}", "No such file or directory")
                error_occurred = True

        # Handle file names file loading
        if file_names_path: 
            if os.path.isfile(file_names_path):
                try:
                    self.file_names, duplicates, line_count, skipped_lines, invalid_lines = load_file_names_from_file(file_names_path)
                    loaded_names = True
                    # Display duplicate file names
                    if duplicates:
                        self.duplicates_text.delete('1.0', tk.END)
                        self.duplicates_text.insert(tk.END, "Duplicate File Names Found (Showing first few):\n")
                        count = 0
                        for name, lines in list(duplicates.items())[:10]: # Limit display
                            self.duplicates_text.insert(tk.END, f"- {name} (Lines: {', '.join(map(str, lines))})\n")
                            count += 1
                        if len(duplicates) > 10:
                             self.duplicates_text.insert(tk.END, f"... and {len(duplicates)-10} more duplicates.")
                    else:
                        self.duplicates_text.delete('1.0', tk.END)
                except Exception as e:
                    self.handle_error(f"Error loading file names: {str(e)} ({file_names_path})", "Invalid file names file")
                    error_occurred = True
            else:
                self.handle_error(f"File names file not found: {file_names_path}", "No such file or directory")
                error_occurred = True

        # Update status label based on what was loaded
        status_parts = []
        if loaded_hashes:
            status_parts.append(f"Loaded {len(self.input_hashes)} hashes")
        if loaded_names:
            status_parts.append(f"Loaded {len(self.file_names)} file names")
        
        if status_parts and not error_occurred:
            self.status_label.config(text=". ".join(status_parts) + ". Ready.")
        elif not hash_file_path and not file_names_path:
             self.status_label.config(text="Status: Idle. Please select files to load.")
        elif not error_occurred: # Files selected but maybe empty or invalid
             self.status_label.config(text="Status: No valid data loaded. Check input files.")
        # Error message is already set by handle_error if error_occurred is True
             
        # Update the preview panel regardless of success/failure
        self.update_preview_panel()

    def refresh_data(self):
        """Refresh both hash and file names data by calling load_data."""
        print("Debug: Refresh Data button clicked. Calling load_data...")
        # Clear status before loading
        self.status_label.config(text="Refreshing data...")
        self.root.update_idletasks()
        # load_data handles getting paths from entries, loading, and updating UI
        self.load_data()

    def scan_and_move_threaded(self):
        """Start the scan and move operation in a separate thread with enhanced security and error handling."""
        if self.is_scanning:
            messagebox.showwarning("Warning", "A scan is already in progress.")
            return

        # Reset cancellation flag
        self.cancel_scan_requested = False

        # Validate inputs with descriptive messages and input sanitization
        try:
            target_folder = self.target_folder_entry.get().strip()
            
            if not target_folder:
                raise ValueError("Please select a source folder.")
                
            # Validate path exists and is a directory
            safe_target_folder = PathSanitizer.sanitize_path(target_folder)
            if not os.path.isdir(safe_target_folder):
                raise ValueError(f"Invalid source folder: {target_folder}")
                
            # Validate we have input data
            if not self.input_hashes and not self.file_names:
                raise ValueError("Please load hashes or file names first.")
                
            # Validate quarantine folder if specified
            quarantine_folder = self.quarantine_folder_entry.get().strip()
            if quarantine_folder:
                safe_quarantine_folder = PathSanitizer.sanitize_path(quarantine_folder)
                # Update global variable - with proper validation this is safe
                global QUARANTINE_FOLDER
                QUARANTINE_FOLDER = str(safe_quarantine_folder)
                
        except ValueError as e:
            # Handle validation errors
            error_code, suggestion = self.error_handler.handle(e, "Input validation")
            self.status_label.config(text=f"Error: {str(e)}")
            messagebox.showerror("Validation Error", f"{str(e)}\n\nSuggestion: {suggestion}")
            return
        except Exception as e:
            # Handle unexpected errors
            error_code, suggestion = self.error_handler.handle(e, "Input validation")
            self.status_label.config(text=f"Error [{error_code}]: {str(e)}")
            messagebox.showerror("Validation Error", f"Error [{error_code}]: {str(e)}\n\nSuggestion: {suggestion}")
            return

        # Reset time tracking
        self.start_time = time.time()
        self.last_update_time = self.start_time
        self.processing_rate = 0

        # Disable scan button, enable cancel button, and update status
        self.is_scanning = True
        self.scan_button.config(state='disabled', text="Scanning...")
        print("Application refreshed.")

    def enable_drag_and_drop(self):
        """Enable drag and drop functionality for entry widgets."""
        self.hash_file_entry.drop_target_register(DND_FILES)
        self.hash_file_entry.dnd_bind('<<Drop>>', self.handle_file_drop)

        self.file_names_entry.drop_target_register(DND_FILES)
        self.file_names_entry.dnd_bind('<<Drop>>', self.handle_file_drop)

    def handle_file_drop(self, event):
        """Handle file drop events for entry widgets."""
        file_path = event.data.strip('{}')  # Remove curly braces if present
        
        # Get the widget that received the drop
        target_widget = event.widget
        
        if target_widget == self.hash_file_entry:
            self.hash_file_entry.delete(0, tk.END)
            self.hash_file_entry.insert(0, file_path)
            self.status_label.config(text=f"Hash file loaded: {file_path}")
            self.update_preview_panel()
            # Automatically load the hashes
            self.load_data()
        elif target_widget == self.file_names_entry:
            self.file_names_entry.delete(0, tk.END)
            self.file_names_entry.insert(0, file_path)
            self.status_label.config(text=f"File names file loaded: {file_path}")
            self.update_preview_panel()
            # Automatically load the file names
            self.load_data()

    def preview_file(self, file_path):
        """Display file information in the preview panel."""
        if not os.path.isfile(file_path):
            return "File does not exist."

        try:
            size = os.path.getsize(file_path)
            file_type = Path(file_path).suffix
            modified_time = os.path.getmtime(file_path)
            modified_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(modified_time))
            
            # Format size in human-readable format
            size_str = self.format_size(size)
            
            preview_text = f"File: {file_path}\n"
            preview_text += f"Size: {size_str}\n"
            preview_text += f"Type: {file_type}\n"
            preview_text += f"Last Modified: {modified_date}\n"
            
            # Add hash information if it's a hash file
            if file_path == self.hash_file_entry.get():
                try:
                    with open(file_path, 'r') as f:
                        lines = f.readlines()
                        valid_hashes = sum(1 for line in lines if line.strip())
                        preview_text += f"Number of Hashes: {valid_hashes}\n"
                except Exception as e:
                    preview_text += f"Error reading hash count: {str(e)}\n"
            
            # Add file count if it's a file names file
            if file_path == self.file_names_entry.get():
                try:
                    with open(file_path, 'r') as f:
                        lines = f.readlines()
                        valid_names = sum(1 for line in lines if line.strip())
                        preview_text += f"Number of File Names: {valid_names}\n"
                except Exception as e:
                    preview_text += f"Error reading file count: {str(e)}\n"
            
            return preview_text
        except Exception as e:
            return f"Error reading file: {str(e)}"

    def format_size(self, size):
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"

    def update_preview_panel(self):
        """Update the preview panel with current file information."""
        hash_file_path = self.hash_file_entry.get()
        file_names_path = self.file_names_entry.get()
        
        preview_text = ""
        
        if hash_file_path:
            preview_text += "Hash File Details:\n" + "=" * 50 + "\n"
            preview_text += self.preview_file(hash_file_path) + "\n"
            
            # Add duplicate hash information
            try:
                _, _, duplicates_count = load_hashes_from_file(hash_file_path)
                if duplicates_count > 0:
                    preview_text += f"Duplicate Hashes: {duplicates_count} duplicates were removed\n"
            except Exception as e:
                preview_text += f"Error checking for duplicate hashes: {str(e)}\n"
        
        if file_names_path:
            preview_text += "\nFile Names Details:\n" + "=" * 50 + "\n"
            preview_text += self.preview_file(file_names_path) + "\n"
            
            # Add file names count and duplicate information
            try:
                _, duplicates, line_count, skipped_lines, invalid_lines = load_file_names_from_file(file_names_path)
                total_duplicates = sum(len(line_numbers) for line_numbers in duplicates.values())
                if duplicates:
                    preview_text += f"\nFile Names Summary:\n" + "-" * 30 + "\n"
                    preview_text += f"Total File Names Read: {line_count}\n"
                    preview_text += f"Total Unique Files: {len(self.file_names)}\n"
                    preview_text += f"Total Duplicate Entries: {total_duplicates}\n"
                    preview_text += f"Duplicate Ratio: {(total_duplicates / (len(self.file_names) + total_duplicates) * 100):.2f}%\n"
                    preview_text += f"Number of Files with Duplicates: {len(duplicates)}\n"
                    preview_text += "-" * 30 + "\n\n"
                    
                    preview_text += "Detailed Duplicate Information:\n" + "-" * 30 + "\n"
                    for file_name, line_numbers in duplicates.items():
                        preview_text += f"File: {file_name}\n"
                        preview_text += f"Found on lines: {', '.join(map(str, line_numbers))}\n"
                        preview_text += "-" * 30 + "\n"
                else:
                    preview_text += f"\nFile Names Summary:\n" + "-" * 30 + "\n"
                    preview_text += f"Total File Names Read: {line_count}\n"
                    preview_text += f"Total Unique Files: {len(self.file_names)}\n"
                    preview_text += "No duplicate file names found.\n"
                    preview_text += "-" * 30 + "\n"
            except Exception as e:
                preview_text += f"Error checking for duplicate file names: {str(e)}\n"
        
        # Update the preview panel
        self.preview_panel.delete('1.0', tk.END)
        self.preview_panel.insert(tk.END, preview_text)

    def toggle_dark_mode(self):
        """Toggle between dark and light mode."""
        self.is_dark_mode = not self.is_dark_mode
        scheme = self.dark_scheme if self.is_dark_mode else self.light_scheme
        self.apply_color_scheme(scheme)
        
        # Update theme button text
        self.theme_button.config(
            text="🌙 Dark Mode" if self.is_dark_mode else "☀️ Light Mode"
        )

    def apply_color_scheme(self, scheme):
        """Apply color scheme to all widgets."""
        # Update root and main frame
        self.root.configure(bg=scheme['bg'])
        
        # Update main frame background and border
        self.main_frame.configure(
            bg=scheme['frame_bg'],
            highlightbackground=scheme['border']
        )

        # Recursively update colors for all widgets starting from main_frame
        self._update_colors_recursive(self.main_frame, scheme)
        
        # Explicitly update progress bar style (already done in recursive, but good to be sure)
        style = ttk.Style()
        style.configure(
            "Rounded.Horizontal.TProgressbar",
            thickness=20,
            borderwidth=0,
            background=scheme['button_bg'],
            troughcolor=scheme['entry_bg']
        )

    def _update_colors_recursive(self, parent, scheme):
        """Recursively update colors for all widgets in a parent container"""
        for widget in parent.winfo_children():
            widget_type = widget.winfo_class()
            
            try:
                if widget_type == 'Label':
                    widget.configure(bg=scheme['frame_bg'], fg=scheme['fg'])
                    if hasattr(widget, 'border_radius'): # Reapply styling if needed
                        widget.config(relief="flat", bd=0, highlightthickness=0)
                elif widget_type == 'Entry':
                    widget.configure(
                        bg=scheme['entry_bg'],
                        fg=scheme['fg'],
                        insertbackground=scheme['fg'],
                        highlightbackground=scheme['border'],
                        highlightcolor=scheme['button_bg'],
                        relief="flat", bd=0, highlightthickness=1 # Reapply styling
                    )
                elif widget_type == 'Button':
                    widget.configure(bg=scheme['button_bg'], fg=scheme['fg'])
                    # Reapply hover bindings
                    if hasattr(widget, 'border_radius'):
                        widget.unbind("<Enter>")
                        widget.unbind("<Leave>")
                        def on_enter(e, button=widget):
                            if not str(button['state']) == 'disabled':
                                button.config(bg="#5e5e5e" if self.is_dark_mode else "#d0d0d0")
                        def on_leave(e, button=widget):
                            if not str(button['state']) == 'disabled':
                                button.config(bg=scheme['button_bg'])
                        widget.bind("<Enter>", on_enter)
                        widget.bind("<Leave>", on_leave)
                elif widget_type == 'Text':
                    widget.configure(
                        bg=scheme['entry_bg'],
                        fg=scheme['fg'],
                        insertbackground=scheme['fg'],
                        highlightbackground=scheme['border'],
                        highlightcolor=scheme['button_bg'],
                        relief="flat", bd=0, highlightthickness=1 # Reapply styling
                    )
                elif widget_type == 'Frame':
                    widget.configure(bg=scheme['frame_bg'])
                    # Recursively update nested widgets
                    self._update_colors_recursive(widget, scheme)
                elif widget_type == 'Canvas':
                    widget.configure(bg=scheme['frame_bg'])
                elif widget_type == 'TScrollbar': # ttk Scrollbar
                    # ttk widgets are styled differently, might need style updates
                    pass # Basic scrollbar colors are hard to change reliably
                elif widget_type == 'TProgressbar': # ttk Progressbar
                    style = ttk.Style()
                    style.configure(
                        "Rounded.Horizontal.TProgressbar",
                        background=scheme['button_bg'],
                        troughcolor=scheme['entry_bg']
                    )
            except tk.TclError as e:
                # Ignore errors for widgets that might not support configuration
                # print(f"Could not configure {widget_type}: {e}")
                pass

    def update_progress_bar(self, current, total):
        """Update progress bar with smoothed time remaining estimates."""
        current_time = time.time()
        
        # Only update every 0.25 seconds to prevent flickering but ensure visibility
        if not hasattr(self, 'last_progress_update') or (current_time - self.last_progress_update) >= 0.25:
            # Calculate progress percentage
            progress_percentage = (current / total) * 100 if total > 0 else 0
            
            # Calculate processing rate and time remaining
            elapsed_time = current_time - self.start_time
            
            # Use exponential moving average for smoother rate calculation
            if not hasattr(self, 'smoothed_rate'):
                self.smoothed_rate = current / elapsed_time if elapsed_time > 0 else 0
            else:
                instant_rate = current / elapsed_time if elapsed_time > 0 else 0
                alpha = 0.2  # Smoothing factor (0.2 = 20% weight to new values)
                self.smoothed_rate = (alpha * instant_rate) + ((1 - alpha) * self.smoothed_rate)
            
            # Calculate estimated time remaining
            remaining_files = total - current
            if self.smoothed_rate > 0:
                estimated_remaining_time = remaining_files / self.smoothed_rate
                
                # Format time remaining in a user-friendly way
                if estimated_remaining_time > 3600:
                    time_str = f"{estimated_remaining_time/3600:.1f} hours"
                elif estimated_remaining_time > 60:
                    time_str = f"{estimated_remaining_time/60:.1f} minutes"
                else:
                    time_str = f"{max(estimated_remaining_time, 0):.0f} seconds"
            else:
                time_str = "Calculating..."
            
            # Update progress bar
            self.progress_bar['value'] = current
            
            # Update label with all information
            status_text = f"Progress: {progress_percentage:.1f}% | "
            status_text += f"Time Remaining: {time_str} | "
            status_text += f"Files: {current:,}/{total:,}"
            
            self.progress_bar_label.config(text=status_text)
            
            # Store last update time
            self.last_progress_update = current_time
            
            # Force GUI update
            self.root.update()

    def handle_error(self, error_message, error_type=None):
        """Handle errors with descriptive messages and suggestions."""
        # Extract the main error message without technical details
        main_error = error_message.split(":")[0].strip()
        
        # Get the appropriate suggestion
        suggestion = self.error_suggestions.get(main_error, "Please try again or contact support if the problem persists.")
        
        # Create a detailed error message
        detailed_message = f"Error: {error_message}\n\nSuggestion: {suggestion}"
        
        # Log the error
        logging.error(f"{error_message} - Suggestion: {suggestion}")
        
        # Show error dialog
        messagebox.showerror("Error", detailed_message)
        
        # Update status label
        self.status_label.config(text=f"Error: {main_error}")

    def show_tutorial(self):
        """Show an interactive tutorial window with detailed step-by-step instructions."""
        tutorial_window = tk.Toplevel(self.root)
        tutorial_window.title("OPTIMUS-VET Tutorial")
        tutorial_window.geometry("700x600")
        
        # Make window modal
        tutorial_window.transient(self.root)
        tutorial_window.grab_set()
        
        # Create main frame with padding
        main_frame = tk.Frame(tutorial_window, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = tk.Label(main_frame, 
                             text="Welcome to OPTIMUS-VET", 
                             font=("Helvetica", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Create a frame for the tutorial content
        content_frame = tk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a text widget with scrollbar
        text_frame = tk.Frame(content_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        tutorial_text = tk.Text(text_frame, 
                              wrap=tk.WORD, 
                              yscrollcommand=scrollbar.set,
                              font=("Helvetica", 10))
        tutorial_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=tutorial_text.yview)
        
        # Tutorial content with detailed feature explanations
        tutorial_content = """
OPTIMUS-VET Tutorial Guide

1. Interface Overview
   • Theme Toggle (🌙/☀️): Switch between dark and light modes
   • Help (❓): Access detailed documentation
   • Tutorial (📚): View this guide
   • Status Label: Shows current operation status
   • Progress Bar: Displays operation progress
   • Preview Panel: Shows file details
   • Invalid Hashes Panel: Lists any invalid hash entries

2. File Input Section
   a) Hash File:
      • Click "Browse" to select a text file containing hash values
      • Supported formats: MD5, SHA-1, SHA-256, SHA-512
      • Drag and drop the file directly into the entry field
      • Preview panel shows file size, type, and hash count
      • Invalid hashes are listed in the bottom panel

   b) File Names File (Optional):
      • Click "Browse" to select a text file with file names
      • One file name per line
      • Drag and drop the file directly into the entry field
      • Preview panel shows file count and details

3. Folder Selection
   a) Source Folder:
      • Click "Browse" to select where to search for files
      • The application will scan all subdirectories
      • Ensure you have read permissions

   b) Destination Folder:
      • Click "Browse" to select where matched files will be moved
      • Will be created if it doesn't exist
      • Ensure you have write permissions

4. Operation Controls
   a) Load Button:
      • Loads and validates hash/file name data
      • Updates preview panel with file details
      • Shows status in status label

   b) Refresh Data Button:
      • Reloads data from the input files
      • Useful if files have been modified
      • Updates preview and status

   c) Refresh Button:
      • Resets the entire application
      • Clears all input fields
      • Cancels any ongoing scan
      • Resets progress and status

   d) Scan and Move Button:
      • Starts the file scanning process
      • Disables during scanning
      • Shows progress and estimated time
      • Generates reports when complete

5. Progress Tracking
   • Progress Bar: Shows percentage complete
   • Time Remaining: Estimated completion time
   • Files Processed: Current/total count
   • Status Label: Current operation status
   • Preview Panel: Updates with file details

6. Results and Reports
   • matches_report.txt: Detailed text report
   • moved_files_report.xlsx: Excel spreadsheet
   • Invalid hashes panel: Lists problematic entries
   • Status label: Shows operation summary
   • Preview panel: Shows file statistics

7. Advanced Features
   • Drag and Drop: Support for file input
   • Dark/Light Mode: Customize interface
   • File Preview: Real-time file information
   • Progress Estimation: Time remaining calculation
   • Error Handling: Detailed error messages
   • Logging: Operation history in duplicate_report.log

8. Best Practices
   • Use text files (.txt) for input
   • Ensure sufficient disk space
   • Close files in other applications
   • Check file permissions
   • Monitor the status label
   • Review preview panel before scanning
   • Check invalid hashes panel for issues

Need more help? Click the "Help" button for detailed documentation.
"""
        
        # Insert tutorial content
        tutorial_text.insert(tk.END, tutorial_content)
        tutorial_text.config(state=tk.DISABLED)  # Make text read-only
        
        # Add close button
        close_button = tk.Button(main_frame, 
                               text="Close Tutorial", 
                               command=tutorial_window.destroy,
                               bg=self.dark_scheme['button_bg'],
                               fg=self.dark_scheme['fg'],
                               bd=2,
                               relief='flat',
                               height=1)
        close_button.pack(pady=(20, 0))
        
        # Apply color scheme
        self.apply_tutorial_colors(tutorial_window)

    def show_reports_menu(self):
        """Show a menu of available report options."""
        # Debug logging
        print(f"Debug: Opening reports menu")
        print(f"Debug: Scan data status - Matches: {len(self.matches)}, Moved Files: {len(self.moved_files_info)}")
        
        # Validate scan data
        if not self.matches and not self.moved_files_info:
            print("Debug: No scan data available")
            messagebox.showinfo("Reports", "No scan data available for reports. Please run a scan first.")
            return

        # Validate scan timing data
        if not self.scan_start_time or not self.scan_end_time:
            print("Debug: Missing scan timing data")
            messagebox.showwarning("Reports", "Scan timing data is missing. Some report features may be limited.")
        
        # Validate total counts
        if self.total_files_processed == 0:
            print("Debug: No files were processed")
            messagebox.showwarning("Reports", "No files were processed during the scan. Report data may be incomplete.")

        # Create report window
        report_window = tk.Toplevel(self.root)
        report_window.title("Generate Reports")
        report_window.geometry("500x600")  # Increased height for better visibility
        
        # Make window modal
        report_window.transient(self.root)
        report_window.grab_set()
        
        # Create main frame
        main_frame = tk.Frame(report_window, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title with scan summary
        title_label = tk.Label(main_frame, 
                              text="Report Generation Options", 
                              font=("Helvetica", 14, "bold"))
        title_label.pack(pady=(0, 10))
        
        # Add scan summary
        summary_text = f"Scan Summary:\n"
        summary_text += f"• Files Processed: {self.total_files_processed}\n"
        summary_text += f"• Matches Found: {self.total_files_matched}\n"
        summary_text += f"• Files Moved: {self.total_files_moved}\n"
        summary_text += f"• Errors: {self.total_errors}\n"
        if self.scan_start_time and self.scan_end_time:
            duration = self.scan_end_time - self.scan_start_time
            summary_text += f"• Duration: {duration:.2f} seconds"
        
        summary_label = tk.Label(main_frame, 
                                text=summary_text,
                                justify=tk.LEFT)
        summary_label.pack(pady=(0, 20))
        
        # Report options frame
        options_frame = tk.Frame(main_frame)
        options_frame.pack(fill=tk.BOTH, expand=True)
        
        # Report format selection
        format_label = tk.Label(options_frame, text="Report Format:")
        format_label.pack(pady=(0, 5))
        
        format_var = tk.StringVar(value="excel")
        formats = [
            ("Excel (XLSX)", "excel"),
            ("CSV", "csv"),
            ("JSON", "json"),
            ("HTML", "html")
        ]
        
        for text, value in formats:
            tk.Radiobutton(options_frame, 
                          text=text, 
                          variable=format_var, 
                          value=value).pack(anchor=tk.W)
        
        # Report content selection
        content_label = tk.Label(options_frame, text="Report Content:")
        content_label.pack(pady=(10, 5))
        
        # Create content variables with proper initialization
        content_vars = {
            "summary": tk.BooleanVar(value=True),
            "matched_files": tk.BooleanVar(value=bool(self.matches)),
            "moved_files": tk.BooleanVar(value=bool(self.moved_files_info)),
            "failed_operations": tk.BooleanVar(value=bool(self.failed_moves or self.failed_scans)),
            "statistics": tk.BooleanVar(value=True),
            "timing": tk.BooleanVar(value=bool(self.scan_start_time and self.scan_end_time))
        }
        
        # Add checkboxes with proper state management
        for text, var in content_vars.items():
            cb = tk.Checkbutton(options_frame, 
                              text=text.replace("_", " ").title(), 
                              variable=var)
            cb.pack(anchor=tk.W)
            # Disable checkbox if no data available
            if text == "matched_files" and not self.matches:
                cb.config(state='disabled')
            elif text == "moved_files" and not self.moved_files_info:
                cb.config(state='disabled')
            elif text == "failed_operations" and not (self.failed_moves or self.failed_scans):
                cb.config(state='disabled')
            elif text == "timing" and not (self.scan_start_time and self.scan_end_time):
                cb.config(state='disabled')
        
        # Button frame
        button_frame = tk.Frame(main_frame)
        button_frame.pack(pady=(20, 0))
        
        # Generate report button
        generate_button = tk.Button(button_frame, 
                                  text="Generate Report", 
                                  command=lambda: self.generate_report(
                                      format_var.get(), 
                                      content_vars
                                  ),
                                  bg=self.dark_scheme['button_bg'],
                                  fg=self.dark_scheme['fg'],
                                  bd=2,
                                  relief='flat',
                                  height=1)
        generate_button.pack(side=tk.LEFT, padx=5)
        
        # Visualize data button
        visualize_button = tk.Button(button_frame, 
                                   text="Visualize Data", 
                                   command=self.visualize_matches,
                                   bg=self.dark_scheme['button_bg'],
                                   fg=self.dark_scheme['fg'],
                                   bd=2,
                                   relief='flat',
                                   height=1)
        visualize_button.pack(side=tk.LEFT, padx=5)
        
        # Apply color scheme
        self.apply_tutorial_colors(report_window)
        
        print("Debug: Reports menu created successfully")

    def generate_report(self, format_type, content_vars):
        """Generate comprehensive reports in the selected format."""
        try:
            # Debug logging
            print(f"Debug: Starting report generation with format: {format_type}")
            print(f"Debug: Content variables: {content_vars}")
            print(f"Debug: Matches count: {len(self.matches)}")
            print(f"Debug: Moved files count: {len(self.moved_files_info)}")
            
            # Validate scan data
            if not self.matches and not self.moved_files_info:
                print("Debug: No scan data available for report generation")
                messagebox.showwarning("Report Generation", "No scan data available. Please run a scan first.")
                return

            # Create timestamp for unique filenames
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            print(f"Debug: Generated timestamp: {timestamp}")
            
            # Prepare report data
            report_data = {}
            
            # Add summary data
            if content_vars["summary"].get():
                print("Debug: Adding summary data")
                report_data["summary"] = {
                    "Total Files Processed": self.total_files_processed,
                    "Total Files Matched": self.total_files_matched,
                    "Total Files Moved": self.total_files_moved,
                    "Total Errors": self.total_errors,
                    "Scan Duration": self.calculate_scan_duration(),
                    "Processing Rate": f"{self.calculate_processing_rate():.2f} files/second"
                }
            
            # Add matched files data
            if content_vars["matched_files"].get() and self.matches:
                print("Debug: Adding matched files data")
                report_data["matched_files"] = [
                    {"File": str(match[0]), "Hash": match[1], "Algorithm": match[2]}
                    for match in self.matches
                ]
            
            # Add moved files data
            if content_vars["moved_files"].get() and self.moved_files_info:
                print("Debug: Adding moved files data")
                report_data["moved_files"] = [
                    {"Original Path": str(info[0]), "New Path": str(info[1]), 
                     "Hash": info[2], "Algorithm": info[3]}
                    for info in self.moved_files_info
                ]
            
            # Add failed operations data
            if content_vars["failed_operations"].get():
                print("Debug: Adding failed operations data")
                if self.failed_moves:
                    report_data["failed_moves"] = [
                        {"File": str(fail[0]), "Hash": fail[1], 
                         "Algorithm": fail[2], "Error": fail[3]}
                        for fail in self.failed_moves
                    ]
                if self.failed_scans:
                    report_data["failed_scans"] = [
                        {"File": str(fail[0]), "Error": fail[1]}
                        for fail in self.failed_scans
                    ]
            
            # Add statistics data
            if content_vars["statistics"].get():
                print("Debug: Adding statistics data")
                report_data["statistics"] = {
                    "Success Rate": f"{(self.total_files_moved / self.total_files_matched * 100):.2f}%" if self.total_files_matched > 0 else "N/A",
                    "Error Rate": f"{(self.total_errors / self.total_files_processed * 100):.2f}%" if self.total_files_processed > 0 else "N/A",
                    "Average Processing Time": f"{self.calculate_average_processing_time():.2f} seconds" if self.total_files_processed > 0 else "N/A"
                }
            
            # Add timing data
            if content_vars["timing"].get():
                print("Debug: Adding timing data")
                report_data["timing"] = {
                    "Start Time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.scan_start_time)) if self.scan_start_time else "N/A",
                    "End Time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.scan_end_time)) if self.scan_end_time else "N/A",
                    "Total Duration": self.calculate_scan_duration()
                }
            
            print(f"Debug: Report data prepared: {len(report_data)} sections")
            
            # Generate report based on format
            if format_type == "excel":
                print("Debug: Generating Excel report")
                self.generate_excel_report(report_data, timestamp)
            elif format_type == "csv":
                print("Debug: Generating CSV report")
                self.generate_csv_report(report_data, timestamp)
            elif format_type == "json":
                print("Debug: Generating JSON report")
                self.generate_json_report(report_data, timestamp)
            elif format_type == "html":
                print("Debug: Generating HTML report")
                self.generate_html_report(report_data, timestamp)
            else:
                raise ValueError(f"Unsupported report format: {format_type}")
            
            print("Debug: Report generation completed successfully")
            messagebox.showinfo("Success", "Report generated successfully!")
            
        except Exception as e:
            print(f"Debug: Error generating report: {str(e)}")
            self.handle_error(f"Error generating report: {str(e)}", "Report Generation Error")

    def generate_csv_report(self, report_data, timestamp):
        """Generate CSV reports for each section."""
        for section, data in report_data.items():
            if isinstance(data, list):
                filename = f"optimus_vet_{section}_{timestamp}.csv"
                pd.DataFrame(data).to_csv(filename, index=False)
            elif isinstance(data, dict):
                filename = f"optimus_vet_{section}_{timestamp}.csv"
                pd.DataFrame([data]).to_csv(filename, index=False)

    def generate_json_report(self, report_data, timestamp):
        """Generate JSON report."""
        filename = f"optimus_vet_report_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=4)

    def generate_html_report(self, report_data, timestamp):
        """Generate HTML report with styling."""
        filename = f"optimus_vet_report_{timestamp}.html"
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>OPTIMUS-VET Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse: collapse; width: 100%; margin: 10px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                h1, h2 { color: #333; }
                .section { margin: 20px 0; }
            </style>
        </head>
        <body>
            <h1>OPTIMUS-VET Report</h1>
        """
        
        for section, data in report_data.items():
            html_content += f"<div class='section'><h2>{section.replace('_', ' ').title()}</h2>"
            
            if isinstance(data, list):
                if data:
                    html_content += "<table><tr>"
                    for key in data[0].keys():
                        html_content += f"<th>{key.replace('_', ' ').title()}</th>"
                    html_content += "</tr>"
                    
                    for item in data:
                        html_content += "<tr>"
                        for value in item.values():
                            html_content += f"<td>{value}</td>"
                        html_content += "</tr>"
                    html_content += "</table>"
            elif isinstance(data, dict):
                html_content += "<table>"
                for key, value in data.items():
                    html_content += f"<tr><th>{key.replace('_', ' ').title()}</th><td>{value}</td></tr>"
                html_content += "</table>"
            
            html_content += "</div>"
        
        html_content += "</body></html>"
        
        with open(filename, 'w') as f:
            f.write(html_content)

    def calculate_scan_duration(self):
        """Calculate the total scan duration."""
        if self.scan_start_time and self.scan_end_time:
            duration = self.scan_end_time - self.scan_start_time
            hours = int(duration // 3600)
            minutes = int((duration % 3600) // 60)
            seconds = int(duration % 60)
            return f"{hours:.0f}h {minutes:.0f}m {seconds:.0f}s"
        return "N/A"

    def calculate_processing_rate(self):
        """Calculate the average processing rate."""
        if self.scan_start_time and self.scan_end_time:
            duration = self.scan_end_time - self.scan_start_time
            return self.total_files_processed / duration if duration > 0 else 0
        return 0

    def calculate_average_processing_time(self):
        """Calculate the average time to process each file."""
        if self.total_files_processed > 0 and self.scan_start_time and self.scan_end_time:
            duration = self.scan_end_time - self.scan_start_time
            return duration / self.total_files_processed
        return 0

    def visualize_matches(self):
        """Create visualizations for hash matches."""
        if not self.matches:
            messagebox.showinfo("Visualization", "No scan data available for visualization.")
            return

        # Create visualization window
        viz_window = tk.Toplevel(self.root)
        viz_window.title("Hash Match Visualizations")
        viz_window.geometry("1000x800")  # Increased window size
        
        # Make window modal
        viz_window.transient(self.root)
        viz_window.grab_set()
        
        # Create main frame
        main_frame = tk.Frame(viz_window, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = tk.Label(main_frame, 
                              text="Hash Match Analysis", 
                              font=("Helvetica", 14, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Create notebook for multiple visualizations
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Algorithm Distribution Tab
        algo_frame = ttk.Frame(notebook)
        notebook.add(algo_frame, text="Algorithm Distribution")
        
        # Create figure for algorithm distribution (bar chart)
        fig_algo = plt.figure(figsize=(10, 6))
        algorithms = [match[2] for match in self.matches]
        algo_counts = Counter(algorithms)
        
        # Create subplot for bar chart
        ax1 = fig_algo.add_subplot(121)
        ax1.bar(algo_counts.keys(), algo_counts.values(), color='blue', alpha=0.7)
        ax1.set_title("Hash Match Distribution by Algorithm")
        ax1.set_xlabel("Algorithm")
        ax1.set_ylabel("Count")
        plt.setp(ax1.get_xticklabels(), rotation=45)
        
        # Create subplot for pie chart
        ax2 = fig_algo.add_subplot(122)
        ax2.pie(algo_counts.values(), labels=algo_counts.keys(), autopct='%1.1f%%', 
                colors=['#FF9999', '#66B2FF', '#99FF99', '#FFCC99'])
        ax2.set_title("Algorithm Distribution (Pie Chart)")
        
        # Add canvas to frame
        canvas_algo = FigureCanvasTkAgg(fig_algo, master=algo_frame)
        canvas_algo.draw()
        canvas_algo.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # File Size Distribution Tab
        size_frame = ttk.Frame(notebook)
        notebook.add(size_frame, text="File Size Distribution")
        
        # Create figure for file size distribution
        fig_size = plt.figure(figsize=(10, 6))
        file_sizes = [os.path.getsize(match[0]) for match in self.matches]
        
        # Create subplot for linear scale
        ax1 = fig_size.add_subplot(121)
        ax1.hist(file_sizes, bins=50, color='green', alpha=0.7)
        ax1.set_title("File Size Distribution (Linear Scale)")
        ax1.set_xlabel("File Size (bytes)")
        ax1.set_ylabel("Count")
        
        # Create subplot for logarithmic scale
        ax2 = fig_size.add_subplot(122)
        ax2.hist(file_sizes, bins=50, color='green', alpha=0.7)
        ax2.set_title("File Size Distribution (Log Scale)")
        ax2.set_xlabel("File Size (bytes)")
        ax2.set_ylabel("Count")
        ax2.set_xscale('log')
        
        # Add canvas to frame
        canvas_size = FigureCanvasTkAgg(fig_size, master=size_frame)
        canvas_size.draw()
        canvas_size.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # File Type Distribution Tab
        type_frame = ttk.Frame(notebook)
        notebook.add(type_frame, text="File Type Distribution")
        
        # Create figure for file type distribution
        fig_type = plt.figure(figsize=(10, 6))
        file_types = [Path(match[0]).suffix.lower() for match in self.matches]
        type_counts = Counter(file_types)
        
        # Sort by count in descending order
        sorted_types = dict(sorted(type_counts.items(), key=lambda x: x[1], reverse=True))
        
        # Create bar chart
        plt.bar(sorted_types.keys(), sorted_types.values(), color='orange', alpha=0.7)
        plt.title("File Type Distribution")
        plt.xlabel("File Extension")
        plt.ylabel("Count")
        plt.xticks(rotation=45)
        
        # Add canvas to frame
        canvas_type = FigureCanvasTkAgg(fig_type, master=type_frame)
        canvas_type.draw()
        canvas_type.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Time Distribution Tab
        time_frame = ttk.Frame(notebook)
        notebook.add(time_frame, text="Time Distribution")
        
        # Create figure for time distribution
        fig_time = plt.figure(figsize=(10, 6))
        file_times = [os.path.getmtime(match[0]) for match in self.matches]
        file_dates = [time.strftime('%Y-%m-%d', time.localtime(t)) for t in file_times]
        date_counts = Counter(file_dates)
        
        # Sort dates
        sorted_dates = dict(sorted(date_counts.items()))
        
        # Create bar chart
        plt.bar(sorted_dates.keys(), sorted_dates.values(), color='purple', alpha=0.7)
        plt.title("File Modification Date Distribution")
        plt.xlabel("Date")
        plt.ylabel("Count")
        plt.xticks(rotation=45)
        
        # Add canvas to frame
        canvas_time = FigureCanvasTkAgg(fig_time, master=time_frame)
        canvas_time.draw()
        canvas_time.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Success/Failure Analysis Tab
        success_frame = ttk.Frame(notebook)
        notebook.add(success_frame, text="Success/Failure Analysis")
        
        # Create figure for success/failure analysis
        fig_success = plt.figure(figsize=(10, 6))
        
        # Calculate success and failure rates
        total_operations = len(self.moved_files_info) + len(self.failed_moves)
        success_rate = len(self.moved_files_info) / total_operations if total_operations > 0 else 0
        failure_rate = len(self.failed_moves) / total_operations if total_operations > 0 else 0
        
        # Create pie chart
        plt.pie([success_rate, failure_rate], 
                labels=['Success', 'Failure'],
                colors=['#4CAF50', '#F44336'],
                autopct='%1.1f%%')
        plt.title("Operation Success/Failure Rate")
        
        # Add canvas to frame
        canvas_success = FigureCanvasTkAgg(fig_success, master=success_frame)
        canvas_success.draw()
        canvas_success.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add close button
        close_button = tk.Button(main_frame, 
                               text="Close Visualizations", 
                               command=viz_window.destroy,
                               bg=self.dark_scheme['button_bg'],
                               fg=self.dark_scheme['fg'],
                               bd=2,
                               relief='flat',
                               height=1)
        close_button.pack(pady=(20, 0))
        
        # Apply color scheme
        self.apply_tutorial_colors(viz_window)

    def show_help(self):
        """Show help information in a new window."""
        help_window = tk.Toplevel(self.root)
        help_window.title("OPTIMUS-VET Help")
        help_window.geometry("700x600")
        
        # Make window modal
        help_window.transient(self.root)
        help_window.grab_set()
        
        # Create main frame with padding
        main_frame = tk.Frame(help_window, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = tk.Label(main_frame, 
                             text="OPTIMUS-VET Help", 
                             font=("Helvetica", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Create a frame for the help content
        content_frame = tk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a text widget with scrollbar
        text_frame = tk.Frame(content_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        help_text = tk.Text(text_frame, 
                           wrap=tk.WORD, 
                           yscrollcommand=scrollbar.set,
                           font=("Helvetica", 10))
        help_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=help_text.yview)
        
        # Help content
        help_content = """
OPTIMUS-VET Help Guide

1. Getting Started
   • Load your hash file using the "Hash File" field
   • Optionally load a file names list
   • Select your source and destination folders
   • Click "Load Hashes/File Names" to begin

2. File Requirements
   • Hash files should be text files (.txt)
   • One hash per line
   • Supported formats: MD5, SHA-1, SHA-256, SHA-512
   • File names should be in a text file, one per line

3. Folder Selection
   • Source Folder: Where to search for files
   • Destination Folder: Where matched files will be moved

4. Controls
   • Load: Load hash and file name data
   • Refresh Data: Reload from files
   • Refresh GUI: Reset the application
   • Scan and Move: Start scanning
   • Reports: Generate detailed reports

5. Features
   • Drag and drop file support
   • Dark/Light mode toggle
   • Progress tracking
   • Time estimation
   • File preview
   • Multiple report formats
   • Data visualization

6. Error Handling
   • Invalid hashes are displayed
   • Detailed error messages
   • Suggested solutions
   • Operation logging

7. Reports
   • Excel (XLSX)
   • CSV
   • JSON
   • HTML
   • Visual charts and graphs

8. Visualizations
   • Algorithm distribution
   • File size distribution
   • File type analysis
   • Time distribution
   • Success/failure rates

For more detailed information, click the Tutorial button.
Need more help? Contact support at support@optimus-vet.com
"""
        
        # Insert help content
        help_text.insert(tk.END, help_content)
        help_text.config(state=tk.DISABLED)  # Make text read-only
        
        # Add close button
        close_button = tk.Button(main_frame, 
                               text="Close Help", 
                               command=help_window.destroy,
                               bg=self.dark_scheme['button_bg'],
                               fg=self.dark_scheme['fg'],
                               bd=2,
                               relief='flat',
                               height=1)
        close_button.pack(pady=(20, 0))
        
        # Apply color scheme
        self.apply_tutorial_colors(help_window)

    def apply_tutorial_colors(self, window):
        """Apply color scheme to tutorial, help, or reports window."""
        scheme = self.dark_scheme if self.is_dark_mode else self.light_scheme
        
        # Configure window background
        window.configure(bg=scheme['bg'])
        
        # Update all widgets in the window recursively
        self._apply_popup_colors_recursive(window, scheme)

    # Add the recursive helper method
    def _apply_popup_colors_recursive(self, parent, scheme):
        """Recursively apply colors to widgets within popup windows."""
        for widget in parent.winfo_children():
            widget_class = widget.winfo_class()
            
            try:
                if widget_class == 'Frame':
                    widget.configure(bg=scheme['frame_bg'])
                    # Recursively update nested widgets
                    self._apply_popup_colors_recursive(widget, scheme)
                elif widget_class == 'Label':
                    widget.configure(bg=scheme['frame_bg'], fg=scheme['fg'])
                elif widget_class == 'Text':
                    widget.configure(
                        bg=scheme['entry_bg'], fg=scheme['fg'], insertbackground=scheme['fg'],
                        relief='flat', bd=0, highlightthickness=1,
                        highlightbackground=scheme['border'], highlightcolor=scheme['button_bg']
                    )
                elif widget_class == 'Button':
                    widget.configure(
                        bg=scheme['button_bg'], fg=scheme['fg'], relief='flat', bd=0, 
                        highlightthickness=0, activebackground=scheme['border'], 
                        activeforeground=scheme['fg']
                    )
                    # Add hover effect
                    widget.unbind("<Enter>")
                    widget.unbind("<Leave>")
                    def on_enter(e, btn=widget):
                        if str(btn['state']) != 'disabled': btn.config(bg="#5e5e5e" if self.is_dark_mode else "#d0d0d0")
                    def on_leave(e, btn=widget):
                        if str(btn['state']) != 'disabled': btn.config(bg=scheme['button_bg'])
                    widget.bind("<Enter>", on_enter)
                    widget.bind("<Leave>", on_leave)
                elif widget_class == 'Radiobutton':
                    widget.configure(
                        bg=scheme['frame_bg'], fg=scheme['fg'], selectcolor=scheme['button_bg'],
                        activebackground=scheme['frame_bg'], activeforeground=scheme['fg'],
                        highlightthickness=0, bd=0
                    )
                elif widget_class == 'Checkbutton':
                     widget.configure(
                        bg=scheme['frame_bg'], fg=scheme['fg'], selectcolor=scheme['button_bg'],
                        activebackground=scheme['frame_bg'], activeforeground=scheme['fg'],
                        highlightthickness=0, bd=0
                    )
                elif widget_class == 'TScrollbar':
                    pass # ttk styling needed
                elif widget_class == 'TNotebook':
                    style = ttk.Style()
                    style.configure('TNotebook', background=scheme['frame_bg'])
                    style.configure('TNotebook.Tab', 
                                    foreground=scheme['fg'], background=scheme['button_bg'])
                    style.map('TNotebook.Tab', 
                              background=[('selected', scheme['frame_bg'])],
                              foreground=[('selected', scheme['fg'])])
                    widget.configure(style='TNotebook')
                    # Recursively style frames within tabs
                    for tab_id in widget.tabs():
                        tab_frame = widget.nametowidget(widget.tab(tab_id, "window"))
                        if isinstance(tab_frame, (tk.Frame, ttk.Frame)):
                            self._apply_popup_colors_recursive(tab_frame, scheme)
                        
            except tk.TclError:
                # Ignore configuration errors for incompatible widgets
                pass

    def browse_hash_file(self):
        """Open file dialog to select hash file."""
        file_path = filedialog.askopenfilename(
            title="Select Hash File",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            self.hash_file_entry.delete(0, tk.END)
            self.hash_file_entry.insert(0, file_path)
            self.status_label.config(text=f"Selected hash file: {file_path}")
            self.update_preview_panel()

    # Replace the current rounding methods with functional ones
    def round_button(self, button, radius=15): # Increase default radius effect
        """Create a more modern looking button with pseudo-rounded appearance."""
        button.config(
            relief="flat",
            bd=0,
            highlightthickness=0,
            padx=15,        # Increased horizontal padding
            pady=8,         # Increased vertical padding
            cursor="hand2" 
        )
        
        # Add hover effect
        def on_enter(e):
            if not str(button['state']) == 'disabled':
                button.config(bg="#5e5e5e" if self.is_dark_mode else "#d0d0d0")
        
        def on_leave(e):
            if not str(button['state']) == 'disabled':
                button.config(bg=self.dark_scheme['button_bg'] if self.is_dark_mode else self.light_scheme['button_bg'])
        
        # Bind hover events
        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)
        
        # Store radius as an attribute for theme switching
        setattr(button, "border_radius", radius)
    
    def round_label(self, label, radius=15):
        """Style label with a more modern appearance."""
        label.config(
            relief="flat",
            bd=0,
            highlightthickness=0,
            pady=8,         # Increased vertical padding
            padx=12        # Increased horizontal padding
        )
        # Store radius as an attribute for theme switching
        setattr(label, "border_radius", radius)
    
    def round_entry(self, entry, radius=15):
        """Style entry with a more modern appearance."""
        scheme = self.dark_scheme if self.is_dark_mode else self.light_scheme
        entry.config(
            relief="flat",
            bd=0,
            highlightthickness=1, # Keep 1px border for focus indication
            # Make border match frame background when *not* focused
            highlightbackground=scheme['frame_bg'], 
            # Use a distinct color when focused
            highlightcolor=scheme['border'], # Use border color for focus
            insertwidth=2,
        )
        # Store radius as an attribute for theme switching
        setattr(entry, "border_radius", radius)
    
    def round_text(self, text, radius=15):
        """Style text widget with a more modern appearance."""
        scheme = self.dark_scheme if self.is_dark_mode else self.light_scheme
        text.config(
            relief="flat",
            bd=0,
            highlightthickness=1, # Keep 1px border for focus indication
            # Make border match frame background when *not* focused
            highlightbackground=scheme['frame_bg'],
             # Use a distinct color when focused
            highlightcolor=scheme['border'], # Use border color for focus
            padx=12,        
            pady=8,         
            insertwidth=2
        )
        # Store radius as an attribute for theme switching
        setattr(text, "border_radius", radius)

    def cancel_scan(self):
        """Cancel the current scan with proper cleanup"""
        if not self.is_scanning:
            return
            
        # Ask for confirmation
        if not messagebox.askyesno("Cancel Scan", 
                                "Are you sure you want to cancel the scan?\nAny files already moved will remain moved."):
            return
            
        try:
            # Set cancellation flag
            self.cancel_scan_requested = True
            self.logger.info("Scan cancellation requested by user")
            
            # Update UI
            self.status_label.config(text="Cancelling scan... Please wait")
            self.progress_bar_label.config(text="Cancelling...")
            self.cancel_button.config(state='disabled')
            
            # Schedule cleanup after a delay to give threads time to terminate
            self.root.after(1000, self.finalize_cancellation)
            
        except Exception as e:
            error_code, suggestion = self.error_handler.handle(e, "Cancelling scan")
            self.logger.error(f"Error during scan cancellation: {str(e)}")
            messagebox.showerror("Error", f"Error cancelling scan: {str(e)}")
            
    def finalize_cancellation(self):
        """Clean up after scan cancellation"""
        # Reset scanning state
        self.reset_scan_state()
        
        # Update UI
        self.status_label.config(text="Scan cancelled by user")
        self.progress_bar_label.config(text="Ready")
        self.progress_bar['value'] = 0
        
        # Inform user
        messagebox.showinfo("Scan Cancelled", 
                         "The scan was cancelled.\nAny files that were already moved remain in the destination folder.")
        
        self.logger.info("Scan cancellation completed")
        
    def reset_scan_state(self):
        """Reset the scanning state and UI elements."""
        self.is_scanning = False
        self.cancel_scan_requested = False
        self.scan_button.config(state='normal', text="Scan and Move")
        self.cancel_button.config(state='disabled')
        self.scan_thread = None
        self.start_time = 0
        self.last_update_time = 0
        self.processing_rate = 0

    def _update_layout(self, width, height):
        """Update the layout based on window size changes.
        
        Args:
            width: Current window width
            height: Current window height
        """
        try:
            # Adjust column widths based on window size
            middle_col_width = int(width * 0.6)
            side_col_width = int(width * 0.2)
            
            self.main_frame.grid_columnconfigure(0, minsize=side_col_width)
            self.main_frame.grid_columnconfigure(1, minsize=middle_col_width)
            self.main_frame.grid_columnconfigure(2, minsize=side_col_width)
            
            # Adjust text widget heights based on window height
            text_height = max(5, int(height * 0.1))
            
            if hasattr(self, 'preview_panel'):
                self.preview_panel.config(height=text_height)
                
            if hasattr(self, 'invalid_hashes_text'):
                self.invalid_hashes_text.config(height=int(text_height * 0.7))
                
            if hasattr(self, 'duplicates_text'):
                self.duplicates_text.config(height=int(text_height * 0.7))
                
            # Update the window title with version
            app_version = "1.0.1"  # Update this with your version number
            self.root.title(f"OPTIMUS-VET v{app_version}")
            
            self.logger.debug(f"Layout updated: width={width}, height={height}")
            
        except Exception as e:
            # Silently log errors without disrupting the UI
            if hasattr(self, 'logger'):
                self.logger.error(f"Error updating layout: {str(e)}")
            else:
                print(f"Error updating layout: {str(e)}")

    def browse_file_names_file(self):
        """Open file dialog to select file names file."""
        file_path = filedialog.askopenfilename(
            title="Select File Names File",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                self.file_names, duplicates, line_count, skipped_lines, invalid_lines = load_file_names_from_file(file_path)
                self.file_names_entry.delete(0, tk.END)
                self.file_names_entry.insert(0, file_path)
                self.status_label.config(text=f"Loaded {len(self.file_names)} file names.")
                self.update_preview_panel()
            except Exception as e:
                self.status_label.config(text=f"Error loading file names: {str(e)}")
                if hasattr(self, 'logger'):
                    self.logger.error(f"Error loading file names: {str(e)}")

    def browse_target_folder(self):
        """Open a dialog to select the source folder and update the entry."""
        folder_path = filedialog.askdirectory(title="Select Target Folder")
        if folder_path:
            self.target_folder_entry.delete(0, tk.END)
            self.target_folder_entry.insert(0, folder_path)
            self.status_label.config(text="Source folder set.")
            if hasattr(self, 'logger'):
                self.logger.info(f"Source folder set to {folder_path}")

    def browse_quarantine_folder(self):
        """Open a dialog to select the quarantine/destination folder and update the entry."""
        folder_path = filedialog.askdirectory(title="Select Quarantine Folder")
        if folder_path:
            self.quarantine_folder_entry.delete(0, tk.END)
            self.quarantine_folder_entry.insert(0, folder_path)
            self.status_label.config(text="Destination folder set.")
            if hasattr(self, 'logger'):
                self.logger.info(f"Destination folder set to {folder_path}")

    def refresh_app(self):
        """Refresh the application to its initial state."""
        # Cancel any ongoing scan
        if self.is_scanning:
            self.is_scanning = False
            if self.scan_thread and self.scan_thread.is_alive():
                self.scan_thread.join(timeout=1.0)

        # Reset UI elements
        self.hash_file_entry.delete(0, tk.END)
        self.file_names_entry.delete(0, tk.END)
        self.target_folder_entry.delete(0, tk.END)
        self.quarantine_folder_entry.delete(0, tk.END)
        self.status_label['text'] = "Status: Idle"
        self.progress_bar['value'] = 0
        self.progress_bar_label['text'] = "Progress: 0% | Time Remaining: Ready"
        self.input_hashes = set()
        self.file_names = set()
        self.invalid_hashes_text.delete('1.0', tk.END)
        self.preview_panel.delete('1.0', tk.END)
        self.scan_button.config(state='normal', text="Scan and Move")
        self.cancel_button.config(state='disabled')
        self.start_time = 0
        self.last_update_time = 0
        self.processing_rate = 0
        if hasattr(self, 'logger'):
            self.logger.info("Application refreshed.")

if __name__ == "__main__":
    # Enable DPI awareness for sharper UI on high-resolution displays
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass  # Continue if this fails

    root = TkinterDnD.Tk()  # Use TkinterDnD instead of regular Tk
    
    # Set the window title and icon
    root.title("OPTIMUS-VET Hash Scanner")
    try:
        root.iconbitmap("Forensics_Icon.ico")  # Use existing icon file
    except:
        pass  # Continue if icon file is not found
    
    # Set the window size and position
    window_width = 800
    window_height = 750
    
    # Get screen dimensions
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    
    # Calculate position coordinates
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    
    # Set window size and position
    root.geometry(f"{window_width}x{window_height}+{x}+{y}")
    
    # Set minimum window size
    root.minsize(700, 600)
    
    # Try to set a modern-looking theme if available
    try:
        root.tk.call("source", "azure.tcl")
        root.tk.call("set_theme", "dark")
    except Exception:
        pass  # Continue with default theme if custom theme is not available
    
    # Create the app instance
    app = HashVettingApp(root)
    
    # Start the main event loop
    root.mainloop()
