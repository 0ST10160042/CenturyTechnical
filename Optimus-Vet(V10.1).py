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


# Constants
# Removed hardcoded paths to make the script independent

# Configure logging
logging.basicConfig(
    filename='duplicate_report.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def load_hashes_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            valid_hashes = set()
            invalid_hashes = []
            duplicates_count = 0
            seen_hashes = set()
            for line in lines:
                print(f"Original line: '{line}'")  # Debugging: Print original line
                hash_value = line.strip()
                print(f"Processed line: '{hash_value}'")  # Debugging: Print processed line
                # Skip empty lines or lines with only whitespace
                if not hash_value:
                    continue
                
                lower_hash_value = hash_value.lower()
                if (re.fullmatch(r'[a-fA-F0-9]{32}', lower_hash_value) or  # MD5
                    re.fullmatch(r'[a-fA-F0-9]{40}', lower_hash_value) or  # SHA-1
                    re.fullmatch(r'[a-fA-F0-9]{64}', lower_hash_value) or  # SHA-256
                    re.fullmatch(r'[a-fA-F0-9]{128}', lower_hash_value)):  # SHA-512
                    if lower_hash_value in seen_hashes:
                        duplicates_count += 1
                    else:
                        valid_hashes.add(lower_hash_value)
                        seen_hashes.add(lower_hash_value)
                else:
                    invalid_hashes.append(hash_value)
                    print(f"Invalid hash detected: {hash_value}")  # Debugging: Print invalid hash
            if invalid_hashes:
                logging.warning(f"Invalid hashes in {file_path}: {', '.join(invalid_hashes)}")
            if duplicates_count > 0:
                logging.info(f"{len(seen_hashes) - len(valid_hashes)} duplicate hashes were removed.")
            return valid_hashes, invalid_hashes, len(seen_hashes) - len(valid_hashes)
    except Exception as e:
        logging.error(f"Error processing hash file {file_path}: {str(e)}")
        print(f"Debug: Error processing hash file {file_path}: {str(e)}")
        raise

def load_file_names_from_file(file_path):
    """Load file names from a text file with enhanced error handling and support for all file types."""
    print(f"Debug: Attempting to load file names from: {file_path}")
    
    # Try different encodings
    encodings = ['utf-8', 'latin1', 'cp1252', 'iso-8859-1', 'utf-16', 'utf-32']
    last_error = None
    duplicates = {}
    
    for encoding in encodings:
        try:
            print(f"Debug: Trying encoding: {encoding}")
            with open(file_path, 'r', encoding=encoding) as file:
                # Read all lines and process each one
                file_names = set()
                line_count = 0
                skipped_lines = 0
                invalid_lines = []
                
                for line in file:
                    line_count += 1
                    # Strip whitespace but preserve the exact file name
                    file_name = line.strip()
                    
                    if not file_name:  # Skip empty lines
                        skipped_lines += 1
                        continue
                        
                    # Remove any quotes if present (both single and double)
                    file_name = file_name.strip('"\'')
                    
                    # Handle Windows path separators
                    file_name = file_name.replace('\\', '/')
                    
                    # Validate file name
                    if any(char in file_name for char in ['<', '>', ':', '"', '/', '\\', '|', '?', '*']):
                        invalid_lines.append((line_count, file_name))
                        continue
                    
                    # Track duplicates
                    if file_name in file_names:
                        if file_name not in duplicates:
                            duplicates[file_name] = []
                        duplicates[file_name].append(line_count)
                    else:
                        file_names.add(file_name)
                    
                    print(f"Debug: Added file name: '{file_name}'")
                
                print(f"Debug: Successfully loaded {len(file_names)} file names from {line_count} lines using {encoding} encoding")
                print(f"Debug: Skipped {skipped_lines} empty lines")
                if invalid_lines:
                    print(f"Debug: Found {len(invalid_lines)} invalid file names:")
                    for line_num, name in invalid_lines:
                        print(f"  Line {line_num}: '{name}'")
                
                logging.info(f"Loaded {len(file_names)} file names from {line_count} lines in {file_path} using {encoding} encoding")
                logging.info(f"Skipped {skipped_lines} empty lines")
                if invalid_lines:
                    logging.warning(f"Found {len(invalid_lines)} invalid file names")
                
                # Log file type distribution
                file_types = {}
                for name in file_names:
                    ext = os.path.splitext(name)[1].lower()
                    file_types[ext] = file_types.get(ext, 0) + 1
                print(f"Debug: File type distribution: {file_types}")
                logging.info(f"File type distribution: {file_types}")
                
                # Log sample of loaded file names for verification
                print("\nDebug: Sample of loaded file names:")
                sample_size = min(5, len(file_names))
                for name in list(file_names)[:sample_size]:
                    print(f"  '{name}'")
                
                # Log total statistics
                print(f"\nDebug: Total Statistics:")
                print(f"  Total lines processed: {line_count}")
                print(f"  Valid file names loaded: {len(file_names)}")
                print(f"  Empty lines skipped: {skipped_lines}")
                print(f"  Invalid file names: {len(invalid_lines)}")
                print(f"  Unique file extensions: {len(file_types)}")
                print(f"  Duplicate entries: {len(duplicates)}")
                
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

def secure_move(file_path, quarantine_folder):
    """Move file to quarantine with conflict resolution and special handling for Outlook files."""
    original_path = file_path.resolve()
    dest_path = Path(quarantine_folder) / file_path.name
    attempt = 1

    try:
        # Check if file is an Outlook data file
        if file_path.suffix.lower() in ['.pst', '.ost']:
            logging.warning(f"Skipping Outlook data file: {file_path}")
            return None, f"Skipped Outlook data file: {file_path} (These files cannot be moved while Outlook is running)"

        # Check if file exists and is accessible
        if not file_path.exists():
            return None, f"File not found: {file_path}"

        while True:
            try:
                if not dest_path.exists():
                    # Ensure destination directory exists
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    # Optionally reset permissions before moving
                    try:
                        set_windows_permissions(file_path)
                    except Exception as perm_error:
                        logging.warning(f"Permission setting failed for {file_path}: {str(perm_error)}")
                    
                    shutil.move(str(original_path), str(dest_path))
                    return dest_path, None
                
                # Handle filename conflicts
                new_name = f"{file_path.stem}_conflict{attempt}{file_path.suffix}"
                dest_path = dest_path.with_name(new_name)
                attempt += 1
                
            except PermissionError:
                return None, f"Permission denied: {file_path}"
            except FileNotFoundError:
                return None, f"File not found: {file_path}"
            except OSError as os_error:
                if "being used by another process" in str(os_error):
                    return None, f"File is in use by another process: {file_path}"
                return None, f"OS Error: {str(os_error)}"
            
    except Exception as e:
        error_msg = str(e)
        if "being used by another process" in error_msg:
            return None, f"File is in use by another process: {file_path}"
        elif "Access is denied" in error_msg:
            return None, f"Access denied: {file_path}"
        return None, f"Error moving file: {error_msg}"

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

def find_and_compare_hashes(directory, input_hashes, progress_bar, progress_bar_label, root, file_names=None, algorithms=['md5', 'sha1'], update_progress_callback=None, quarantine_folder=None):
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
    Path(quarantine_folder).mkdir(parents=True, exist_ok=True)
    logging.info(f"Quarantine folder ensured: {quarantine_folder}")

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
                    new_path, error = secure_move(file_path, quarantine_folder)
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
                        new_path, error = secure_move(file_path, quarantine_folder)
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
    os.startfile(quarantine_folder)
    logging.info(f"Opened quarantine folder: {quarantine_folder}")

    # Open generated report
    os.startfile('matches_report.txt')
    logging.info("Opened matches report file")

    return matches, moved_files_info, failed_moves, failed_scans, total_files_processed

class HashVettingApp:

    def __init__(self, root):
        self.root = root
        self.root.title("OPTIMUS-VET")
        
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
        self.main_frame.grid(row=0, column=0, padx=20, pady=20, sticky='nsew')

        # Configure grid weights for main_frame
        for i in range(12):
            self.main_frame.grid_rowconfigure(i, weight=1)
        for i in range(3):
            self.main_frame.grid_columnconfigure(i, weight=1)

        # Create all UI elements
        self.create_ui_elements()

        # Enable drag and drop functionality after UI elements are created
        self.enable_drag_and_drop()

        # Apply color scheme after all UI elements are created
        self.apply_color_scheme(self.dark_scheme)

    def create_ui_elements(self):
        """Create all UI elements."""
        # Add theme toggle button at the top
        self.theme_button = tk.Button(self.main_frame, 
                                    text="🌙 Dark Mode", 
                                    command=self.toggle_dark_mode,
                                    bg=self.dark_scheme['button_bg'],
                                    fg=self.dark_scheme['fg'],
                                    bd=2,
                                    relief='flat',
                                    height=1)
        self.theme_button.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)

        # Add tutorial button next to theme button
        self.tutorial_button = tk.Button(self.main_frame, 
                                       text="📚 Tutorial", 
                                       command=self.show_tutorial,
                                       bg=self.dark_scheme['button_bg'],
                                       fg=self.dark_scheme['fg'],
                                       bd=2,
                                       relief='flat',
                                       height=1)
        self.tutorial_button.grid(row=0, column=2, sticky='nsew', padx=5, pady=5)
        
        # Add a help button in column 1
        self.help_button = tk.Button(self.main_frame, 
                                   text="❓ Help", 
                                   command=self.show_help,
                                   bg=self.dark_scheme['button_bg'],
                                   fg=self.dark_scheme['fg'],
                                   bd=2,
                                   relief='flat',
                                   height=1)
        self.help_button.grid(row=0, column=1, sticky='nsew', padx=5, pady=5)

        # Input fields with reduced width
        self.hash_file_label = tk.Label(self.main_frame, 
                                      text="Hash File:", 
                                      bg=self.dark_scheme['frame_bg'], 
                                      fg=self.dark_scheme['fg'], 
                                      bd=2, 
                                      relief='groove')
        self.hash_file_label.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)
        
        self.hash_file_entry = tk.Entry(self.main_frame, 
                                      width=30, 
                                      bg=self.dark_scheme['entry_bg'], 
                                      fg=self.dark_scheme['fg'], 
                                      insertbackground=self.dark_scheme['fg'],
                                      bd=2, 
                                      relief='groove')
        self.hash_file_entry.grid(row=1, column=1, sticky='nsew', padx=5, pady=5)
        
        self.browse_hash_button = tk.Button(self.main_frame, 
                                          text="Browse", 
                                          command=self.browse_hash_file, 
                                          bg=self.dark_scheme['button_bg'], 
                                          fg=self.dark_scheme['fg'], 
                                          bd=2, 
                                          relief='flat', 
                                          height=1)
        self.browse_hash_button.grid(row=1, column=2, sticky='nsew', padx=5, pady=5)
        
        # Input fields for file names
        self.file_names_label = tk.Label(self.main_frame, text="File Names File:", bg=self.dark_scheme['frame_bg'], fg=self.dark_scheme['fg'], bd=2, relief='groove')
        self.file_names_label.grid(row=2, column=0, sticky='nsew', padx=5, pady=5)
        self.file_names_entry = tk.Entry(self.main_frame, width=30, bg=self.dark_scheme['entry_bg'], fg=self.dark_scheme['fg'], insertbackground=self.dark_scheme['fg'], bd=2, relief='groove')
        self.file_names_entry.grid(row=2, column=1, sticky='nsew', padx=5, pady=5)
        self.browse_file_names_button = tk.Button(self.main_frame, text="Browse", command=self.browse_file_names_file, bg=self.dark_scheme['button_bg'], fg=self.dark_scheme['fg'], bd=2, relief='flat', height=1)
        self.browse_file_names_button.grid(row=2, column=2, sticky='nsew', padx=5, pady=5)
        
        # Add preview panel label
        self.preview_label = tk.Label(self.main_frame, text="File Preview:", bg=self.dark_scheme['frame_bg'], fg=self.dark_scheme['fg'], bd=2, relief='groove')
        self.preview_label.grid(row=3, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)

        # Add preview panel with increased height
        self.preview_panel = tk.Text(self.main_frame, height=12, bg=self.dark_scheme['entry_bg'], fg=self.dark_scheme['fg'], wrap='word', bd=2, relief='groove')
        self.preview_panel.grid(row=4, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        
        # Adjust the positions of the existing elements
        self.target_folder_label = tk.Label(self.main_frame, text="Source Folder:", bg=self.dark_scheme['frame_bg'], fg=self.dark_scheme['fg'], bd=2, relief='groove')
        self.target_folder_label.grid(row=5, column=0, sticky='nsew', padx=5, pady=5)
        self.target_folder_entry = tk.Entry(self.main_frame, width=30, bg=self.dark_scheme['entry_bg'], fg=self.dark_scheme['fg'], insertbackground=self.dark_scheme['fg'], bd=2, relief='groove')
        self.target_folder_entry.grid(row=5, column=1, sticky='nsew', padx=5, pady=5)
        self.browse_target_button = tk.Button(self.main_frame, text="Browse", command=self.browse_target_folder, bg=self.dark_scheme['button_bg'], fg=self.dark_scheme['fg'], bd=2, relief='flat', height=1)
        self.browse_target_button.grid(row=5, column=2, sticky='nsew', padx=5, pady=5)
        
        self.quarantine_folder_label = tk.Label(self.main_frame, text="Destination Folder:", bg=self.dark_scheme['frame_bg'], fg=self.dark_scheme['fg'], bd=2, relief='groove')
        self.quarantine_folder_label.grid(row=6, column=0, sticky='nsew', padx=5, pady=5)
        self.quarantine_folder_entry = tk.Entry(self.main_frame, width=30, bg=self.dark_scheme['entry_bg'], fg=self.dark_scheme['fg'], insertbackground=self.dark_scheme['fg'], bd=2, relief='groove')
        self.quarantine_folder_entry.grid(row=6, column=1, sticky='nsew', padx=5, pady=5)
        self.browse_quarantine_button = tk.Button(self.main_frame, text="Browse", command=self.browse_quarantine_folder, bg=self.dark_scheme['button_bg'], fg=self.dark_scheme['fg'], bd=2, relief='flat', height=1)
        self.browse_quarantine_button.grid(row=6, column=2, sticky='nsew', padx=5, pady=5)
        
        # Buttons with reduced height and modern look
        self.button_frame = tk.Frame(self.main_frame, bg=self.dark_scheme['frame_bg'])
        self.button_frame.grid(row=7, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        self.load_button = tk.Button(self.button_frame, text="Load Hashes/File Names", command=self.load_data, bg=self.dark_scheme['button_bg'], fg=self.dark_scheme['fg'], bd=2, relief='flat', height=1, padx=10, pady=2)
        self.load_button.pack(side=tk.LEFT, expand=True, fill='x', padx=3, pady=2)
        
        self.refresh_data_button = tk.Button(self.button_frame, text="Refresh Hashes/File Names", command=self.refresh_data, bg=self.dark_scheme['button_bg'], fg=self.dark_scheme['fg'], bd=2, relief='flat', height=1, padx=10, pady=2)
        self.refresh_data_button.pack(side=tk.LEFT, expand=True, fill='x', padx=3, pady=2)

        self.refresh_gui_button = tk.Button(self.button_frame, text="Refresh", command=self.refresh_app, bg=self.dark_scheme['button_bg'], fg=self.dark_scheme['fg'], bd=2, relief='flat', height=1, padx=10, pady=2)
        self.refresh_gui_button.pack(side=tk.LEFT, expand=True, fill='x', padx=3, pady=2)
        
        # Add thread control variables
        self.scan_thread = None
        self.is_scanning = False
        
        # Update scan button to show scanning state
        self.scan_button = tk.Button(self.main_frame, 
                                   text="Scan and Move", 
                                   bg=self.dark_scheme['button_bg'], 
                                   fg=self.dark_scheme['fg'], 
                                   height=1, 
                                   width=10, 
                                   command=self.scan_and_move_threaded, 
                                   bd=2, 
                                   relief='flat', 
                                   padx=10, 
                                   pady=5)
        self.scan_button.grid(row=8, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        
        self.progress_bar = ttk.Progressbar(self.main_frame, orient='horizontal', length=400, mode='determinate')
        self.progress_bar.grid(row=9, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        
        # Add a label for displaying progress percentage
        self.progress_bar_label = tk.Label(self.main_frame, 
                                         text="Ready", 
                                         bg=self.dark_scheme['frame_bg'], 
                                         fg=self.dark_scheme['fg'], 
                                         bd=2, 
                                         relief='groove')
        self.progress_bar_label.grid(row=10, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        
        self.status_label = tk.Label(self.main_frame, text="Status: Idle", bg=self.dark_scheme['frame_bg'], fg=self.dark_scheme['fg'], bd=2, relief='groove', wraplength=400)
        self.status_label.grid(row=11, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        
        # Add a Text widget for displaying invalid hashes
        self.invalid_hashes_text = tk.Text(self.main_frame, height=5, bg=self.dark_scheme['entry_bg'], fg=self.dark_scheme['fg'], wrap='word')
        self.invalid_hashes_text.grid(row=12, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        
        # Add time tracking variables
        self.start_time = 0
        self.last_update_time = 0
        self.processing_rate = 0  # files per second
        
        # Add Reports button to button frame
        self.reports_button = tk.Button(self.button_frame, 
                                      text="📊 Reports", 
                                      command=self.show_reports_menu,
                                      bg=self.dark_scheme['button_bg'], 
                                      fg=self.dark_scheme['fg'], 
                                      bd=2, 
                                      relief='flat', 
                                      height=1, 
                                      padx=10, 
                                      pady=2)
        self.reports_button.pack(side=tk.LEFT, expand=True, fill='x', padx=3, pady=2)
        
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
        
        # Add a Text widget for displaying duplicate file names
        self.duplicates_label = tk.Label(self.main_frame, text="Duplicate File Names:", bg=self.dark_scheme['frame_bg'], fg=self.dark_scheme['fg'], bd=2, relief='groove')
        self.duplicates_label.grid(row=13, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        
        self.duplicates_text = tk.Text(self.main_frame, height=5, bg=self.dark_scheme['entry_bg'], fg=self.dark_scheme['fg'], wrap='word')
        self.duplicates_text.grid(row=14, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        
    def load_data(self):
        """Load hashes from hash file with enhanced error handling."""
        hash_file_path = self.hash_file_entry.get()
        
        # Handle hash file loading
        if hash_file_path and os.path.isfile(hash_file_path):
            try:
                self.input_hashes, invalid_hashes, duplicates_count = load_hashes_from_file(hash_file_path)
                self.status_label.config(text=f"Loaded {len(self.input_hashes)} valid hashes")
            except FileNotFoundError:
                self.handle_error(f"File not found: {hash_file_path}", "No such file or directory")
            except PermissionError:
                self.handle_error(f"Permission denied: {hash_file_path}", "Permission denied")
            except IOError as e:
                self.handle_error(f"IO Error: {str(e)}", "File in use")
            except Exception as e:
                self.handle_error(f"Error loading hashes: {str(e)}", "Invalid input")
                return
        
        # Handle file names file loading
        file_names_path = self.file_names_entry.get()
        if file_names_path and os.path.isfile(file_names_path):
            try:
                self.file_names, duplicates, line_count, skipped_lines, invalid_lines = load_file_names_from_file(file_names_path)
                self.status_label.config(text=f"Loaded {len(self.file_names)} file names")
            except Exception as e:
                self.handle_error(f"Error loading file names: {str(e)}", "Invalid input")
                return

    def refresh_data(self):
        # Clear any previous status messages
        self.status_label.config(text="")
        
        # Get current paths
        hash_file_path = self.hash_file_entry.get()
        file_names_path = self.file_names_entry.get()
        
        # Clear data structures
        self.input_hashes = set()
        self.file_names = set()
        
        # Reload data if paths exist
        success_message = []
        
        if hash_file_path:
            if os.path.isfile(hash_file_path):
                try:
                    self.input_hashes, invalid_hashes, duplicates_count = load_hashes_from_file(hash_file_path)
                    success_message.append(f"Loaded {len(self.input_hashes)} valid hashes")
                except Exception as e:
                    self.status_label.config(text=f"Error loading hashes: {str(e)}")
                    return
            else:
                self.status_label.config(text="Error: Hash file does not exist")
                return
        
        if file_names_path:
            if os.path.isfile(file_names_path):
                try:
                    self.file_names, duplicates, line_count, skipped_lines, invalid_lines = load_file_names_from_file(file_names_path)
                    success_message.append(f"Loaded {len(self.file_names)} file names")
                except Exception as e:
                    self.status_label.config(text=f"Error loading file names: {str(e)}")
                    return
            else:
                self.status_label.config(text="Error: File names file does not exist")
                return
        
        # Update status with success message if we have one
        if success_message:
            self.status_label.config(text=". ".join(success_message))
        else:
            self.status_label.config(text="No hash file or file names file specified")

    def scan_and_move_threaded(self):
        """Start the scan and move operation in a separate thread with enhanced error handling."""
        if self.is_scanning:
            messagebox.showwarning("Warning", "A scan is already in progress.")
            return

        # Validate inputs with descriptive messages
        target_folder = self.target_folder_entry.get()
        if not target_folder:
            self.handle_error("Please select a source folder.", "Missing data")
            return
        if not os.path.isdir(target_folder):
            self.handle_error(f"Invalid folder: {target_folder}", "Invalid folder")
            return

        quarantine_folder = self.quarantine_folder_entry.get()
        if not quarantine_folder:
            self.handle_error("Please select a destination folder.", "Missing data")
            return
        if not os.path.isdir(quarantine_folder):
            self.handle_error(f"Invalid folder: {quarantine_folder}", "Invalid folder")
            return

        if not self.input_hashes and not self.file_names:
            self.handle_error("Please load hashes or file names first.", "Missing data")
            return

        # Reset time tracking
        self.start_time = time.time()
        self.last_update_time = self.start_time
        self.processing_rate = 0

        # Disable scan button and update status
        self.is_scanning = True
        self.scan_button.config(state='disabled', text="Scanning...")
        self.status_label.config(text="Status: Scanning in progress...")
        self.progress_bar['value'] = 0
        self.progress_bar_label.config(text="Progress: 0% | Time Remaining: Calculating... | Files Processed: 0")

        def processing_thread():
            try:
                # Store scan start time
                self.scan_start_time = time.time()
                
                matches, moved_files_info, failed_moves, failed_scans, total_files_processed = find_and_compare_hashes(
                    directory=target_folder,
                    input_hashes=self.input_hashes,
                    progress_bar=self.progress_bar,
                    progress_bar_label=self.progress_bar_label,
                    root=self.root,
                    file_names=self.file_names,
                    update_progress_callback=self.update_progress_bar,
                    quarantine_folder=quarantine_folder
                )

                # Store scan results in class instance
                self.matches = matches
                self.moved_files_info = moved_files_info
                self.failed_moves = failed_moves
                self.failed_scans = failed_scans
                self.total_files_processed = total_files_processed
                self.total_files_matched = len(matches)
                self.total_files_moved = len(moved_files_info)
                self.total_errors = len(failed_moves) + len(failed_scans)
                
                # Store scan end time
                self.scan_end_time = time.time()

                # Update GUI from main thread
                self.root.after(0, self.update_scan_results, matches, moved_files_info, failed_moves, failed_scans, total_files_processed)

            except Exception as e:
                # Update GUI from main thread with error
                self.root.after(0, self.handle_scan_error, str(e))
            finally:
                # Reset scanning state and progress bar
                self.root.after(0, self.reset_scan_state)

        # Start the processing thread
        self.scan_thread = threading.Thread(target=processing_thread, daemon=True)
        self.scan_thread.start()

    def update_scan_results(self, matches, moved_files_info, failed_moves, failed_scans, total_files_processed):
        """Update the GUI with scan results and store scan data."""
        # Store scan data in class instance
        self.matches = matches
        self.moved_files_info = moved_files_info
        self.failed_moves = failed_moves
        self.failed_scans = failed_scans
        self.total_files_processed = total_files_processed
        self.total_files_matched = len(matches)
        self.total_files_moved = len(moved_files_info)
        self.total_errors = len(failed_moves) + len(failed_scans)
        
        # Store scan timing
        self.scan_end_time = time.time()

        # Update status label with detailed information
        status_text = f"Scan complete. Found {len(matches)} matches, moved {len(moved_files_info)} files."
        if len(failed_moves) > 0:
            status_text += f" {len(failed_moves)} moves failed."
        if len(failed_scans) > 0:
            status_text += f" {len(failed_scans)} scans failed."
        self.status_label.config(text=status_text)

        # Enable the Reports button if scan data exists
        if matches or moved_files_info:
            self.reports_button.config(state='normal')
            print("Debug: Reports button enabled due to scan data availability")
        else:
            self.reports_button.config(state='disabled')
            print("Debug: Reports button disabled - no scan data available")

        # Generate Excel report
        self.generate_excel_report(moved_files_info)

        # Show success message
        messagebox.showinfo(
            "Scan Complete",
            f"Found {len(matches)} matches\nMoved {len(moved_files_info)} files"
        )

    def handle_scan_error(self, error_message):
        """Handle errors during scanning with enhanced error messages."""
        # Determine the type of error
        error_type = None
        if "Permission denied" in error_message:
            error_type = "Permission denied"
        elif "No such file or directory" in error_message:
            error_type = "No such file or directory"
        elif "File is open in another program" in error_message:
            error_type = "File is open in another program"
        elif "Disk full" in error_message:
            error_type = "Disk full"
        elif "Timeout" in error_message:
            error_type = "Timeout"
        elif "Memory error" in error_message:
            error_type = "Memory error"
        
        # Handle the error with appropriate message
        self.handle_error(error_message, error_type)
        self.reset_scan_state()

    def reset_scan_state(self):
        """Reset the scanning state and UI elements."""
        self.is_scanning = False
        self.scan_button.config(state='normal', text="Scan and Move")
        self.scan_thread = None
        self.start_time = 0
        self.last_update_time = 0
        self.processing_rate = 0
        self.progress_bar['value'] = 0
        self.progress_bar_label.config(text="Ready")

    def browse_target_folder(self):
        folder_path = filedialog.askdirectory(title="Select Target Folder")
        self.target_folder_entry.delete(0, tk.END)
        self.target_folder_entry.insert(0, folder_path)

    def browse_quarantine_folder(self):
        folder_path = filedialog.askdirectory(title="Select Quarantine Folder")
        self.quarantine_folder_entry.delete(0, tk.END)
        self.quarantine_folder_entry.insert(0, folder_path)

    def refresh_hashes(self):
        """Refresh the loaded hashes from the file."""
        hash_file_path = self.hash_file_entry.get()
        print(f"Debug: Refreshing hashes from file path: '{hash_file_path}'")  # Debugging: Print the file path being retrieved

        # Check if the file path is empty
        if not hash_file_path:
            self.root.after(0, lambda: self.status_label.config(text="Error: No hash file path provided."))
            print("Error: No hash file path provided.")  # Debugging: Print error message
            return

        # Check if the file exists
        if not os.path.isfile(hash_file_path):
            self.root.after(0, lambda: self.status_label.config(text="Error: Hash file does not exist or is not saved."))
            print("Error: Hash file does not exist or is not saved.")  # Debugging: Print error message
            return

        try:
            # Read lines from the file
            with open(hash_file_path, 'r') as file:
                lines = file.readlines()
            
            self.input_hashes, invalid_hashes, duplicates_count = load_hashes_from_file(hash_file_path)
            # Deduplicate hashes
            self.input_hashes = {h for h in self.input_hashes if re.match(r'^[a-fA-F0-9]{32}$', h) or re.match(r'^[a-fA-F0-9]{40}$', h)}
            if invalid_hashes or duplicates_count > 0:
                invalid_hashes_str = ', '.join(invalid_hashes)
                self.root.after(0, lambda: self.status_label.config(text=f"Refreshed: {len(self.input_hashes)} valid hashes loaded with {duplicates_count} duplicates removed."))
                self.invalid_hashes_text.delete('1.0', tk.END)
                self.invalid_hashes_text.insert(tk.END, f"Invalid hashes: {invalid_hashes_str}")
            else:
                self.root.after(0, lambda: self.status_label.config(text=f"Refreshed: {len(self.input_hashes)} valid hashes loaded"))
                self.invalid_hashes_text.delete('1.0', tk.END)
            print("Refreshed hashes:")
            for h in self.input_hashes:
                print(h)
        except FileNotFoundError:
            self.root.after(0, lambda: self.status_label.config(text="Error: Hash file not found."))
            logging.error("Error: Hash file not found.")
        except IOError as e:
            self.root.after(0, lambda: self.status_label.config(text=f"Error reading hash file: {str(e)}"))
            logging.error(f"Error reading hash file: {str(e)}")
        except Exception as e:
            self.root.after(0, lambda: self.status_label.config(text=f"Error refreshing hashes: {str(e)}"))
            logging.error(f"Error refreshing hashes: {str(e)}")

    def browse_file_names_file(self):
        """Open file dialog to select file names file."""
        file_path = filedialog.askopenfilename(
            title="Select File Names File",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        print(f"Debug: Selected file names file path: {file_path}")  # Debugging: Print the selected file path
        if file_path:
            try:
                self.file_names, duplicates, line_count, skipped_lines, invalid_lines = load_file_names_from_file(file_path)
                self.file_names_entry.delete(0, tk.END)
                self.file_names_entry.insert(0, file_path)
                self.status_label.config(text=f"Loaded {len(self.file_names)} file names.")
                self.update_preview_panel()
                print(f"Debug: File path set in entry: {file_path}")  # Debugging: Print the file path set in the entry
            except Exception as e:
                self.status_label.config(text=f"Error loading file names: {str(e)}")
                logging.error(f"Error loading file names: {str(e)}")

    def generate_excel_report(self, report_data, timestamp):
        """Generate Excel report with detailed file information."""
        filename = f"file_removal_report_{timestamp}.xlsx"
        
        # Create a workbook
        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            # Moved/Deleted Files Sheet
            if "moved_files" in report_data:
                # Create a detailed DataFrame for moved files
                moved_files_data = []
                for info in report_data["moved_files"]:
                    original_path = info["Original Path"]
                    file_info = {
                        'File Name': os.path.basename(original_path),
                        'Original Path': original_path,
                        'New Location': info["New Path"],
                        'File Hash': info["Hash"],
                        'Hash Algorithm': info["Algorithm"],
                        'File Size (bytes)': os.path.getsize(info["New Path"]) if os.path.exists(info["New Path"]) else "N/A",
                        'Last Modified': time.strftime('%Y-%m-%d %H:%M:%S', 
                            time.localtime(os.path.getmtime(info["New Path"]))) if os.path.exists(info["New Path"]) else "N/A",
                        'File Extension': os.path.splitext(original_path)[1],
                    }
                    moved_files_data.append(file_info)
                
                # Convert to DataFrame and write to Excel
                df_moved = pd.DataFrame(moved_files_data)
                df_moved.to_excel(writer, sheet_name="Moved Files", index=False)
                
                # Auto-adjust column widths
                worksheet = writer.sheets["Moved Files"]
                for idx, col in enumerate(df_moved.columns):
                    max_length = max(
                        df_moved[col].astype(str).apply(len).max(),
                        len(col)
                    ) + 2
                    worksheet.column_dimensions[chr(65 + idx)].width = min(max_length, 50)
            
            # Summary Sheet
            if "summary" in report_data:
                summary_df = pd.DataFrame([report_data["summary"]])
                summary_df.to_excel(writer, sheet_name="Summary", index=False)
                
                # Auto-adjust column widths for summary
                worksheet = writer.sheets["Summary"]
                for idx, col in enumerate(summary_df.columns):
                    max_length = max(
                        summary_df[col].astype(str).apply(len).max(),
                        len(col)
                    ) + 2
                    worksheet.column_dimensions[chr(65 + idx)].width = min(max_length, 50)
            
            # Failed Operations Sheet
            if "failed_moves" in report_data:
                failed_moves_data = []
                for fail in report_data["failed_moves"]:
                    fail_info = {
                        'File Name': os.path.basename(fail["File"]),
                        'File Path': fail["File"],
                        'Hash': fail["Hash"],
                        'Algorithm': fail["Algorithm"],
                        'Error': fail["Error"]
                    }
                    failed_moves_data.append(fail_info)
                
                df_failed = pd.DataFrame(failed_moves_data)
                df_failed.to_excel(writer, sheet_name="Failed Operations", index=False)
                
                # Auto-adjust column widths
                worksheet = writer.sheets["Failed Operations"]
                for idx, col in enumerate(df_failed.columns):
                    max_length = max(
                        df_failed[col].astype(str).apply(len).max(),
                        len(col)
                    ) + 2
                    worksheet.column_dimensions[chr(65 + idx)].width = min(max_length, 50)
        
        # Open the generated report
        try:
            os.startfile(filename)
        except Exception as e:
            print(f"Report generated but could not open automatically: {str(e)}")
            messagebox.showinfo("Report Generated", f"Report saved as: {filename}")

    def load_file_names(self):
        """Load file names from file."""
        file_names_file_path = self.file_names_entry.get() or FILE_NAMES_PATH
        if not os.path.isfile(file_names_file_path):
            self.status_label.config(text="Error: File names file does not exist or is not saved.")
            return
        try:
            self.file_names, duplicates, line_count, skipped_lines, invalid_lines = load_file_names_from_file(file_names_file_path)
            
            # Update status with detailed information
            status_text = f"Loaded {len(self.file_names)} file names from {line_count} lines"
            if skipped_lines > 0:
                status_text += f" (skipped {skipped_lines} empty lines)"
            if invalid_lines:
                status_text += f" ({len(invalid_lines)} invalid lines)"
            if duplicates:
                status_text += f" ({len(duplicates)} duplicates found)"
            self.status_label['text'] = status_text
            
            # Display duplicate information
            if duplicates:
                self.duplicates_text.delete('1.0', tk.END)
                self.duplicates_text.insert(tk.END, "Duplicate File Names:\n")
                self.duplicates_text.insert(tk.END, "=" * 50 + "\n")
                for file_name, line_numbers in duplicates.items():
                    self.duplicates_text.insert(tk.END, f"File: {file_name}\n")
                    self.duplicates_text.insert(tk.END, f"Found on lines: {', '.join(map(str, line_numbers))}\n")
                    self.duplicates_text.insert(tk.END, "-" * 50 + "\n")
            else:
                self.duplicates_text.delete('1.0', tk.END)
                self.duplicates_text.insert(tk.END, "No duplicate file names found.")
            
            print("Loaded file names:")
            for name in self.file_names:
                print(name)
        except Exception as e:
            self.status_label['text'] = f"Error loading file names: {str(e)}"
            logging.error(f"Error loading file names: {str(e)}")

    def refresh_file_names(self):
        """Refresh the loaded file names from the file."""
        file_names_file_path = self.file_names_entry.get() or FILE_NAMES_PATH
        print(f"Debug: Refreshing file names from file path: '{file_names_file_path}'")

        if not file_names_file_path:
            self.root.after(0, lambda: self.status_label.config(text="Error: No file names file path provided."))
            print("Error: No file names file path provided.")
            return

        if not os.path.isfile(file_names_file_path):
            self.root.after(0, lambda: self.status_label.config(text="Error: File names file does not exist or is not saved."))
            print("Error: File names file does not exist or is not saved.")
            return

        try:
            self.file_names, duplicates, line_count, skipped_lines, invalid_lines = load_file_names_from_file(file_names_file_path)
            
            # Update status with detailed information
            status_text = f"Refreshed: {len(self.file_names)} file names from {line_count} lines"
            if skipped_lines > 0:
                status_text += f" (skipped {skipped_lines} empty lines)"
            if invalid_lines:
                status_text += f" ({len(invalid_lines)} invalid lines)"
            if duplicates:
                status_text += f" ({len(duplicates)} duplicates found)"
            self.root.after(0, lambda: self.status_label.config(text=status_text))
            
            # Display duplicate information
            if duplicates:
                self.duplicates_text.delete('1.0', tk.END)
                self.duplicates_text.insert(tk.END, "Duplicate File Names:\n")
                self.duplicates_text.insert(tk.END, "=" * 50 + "\n")
                for file_name, line_numbers in duplicates.items():
                    self.duplicates_text.insert(tk.END, f"File: {file_name}\n")
                    self.duplicates_text.insert(tk.END, f"Found on lines: {', '.join(map(str, line_numbers))}\n")
                    self.duplicates_text.insert(tk.END, "-" * 50 + "\n")
            else:
                self.duplicates_text.delete('1.0', tk.END)
                self.duplicates_text.insert(tk.END, "No duplicate file names found.")
            
            print("Refreshed file names:")
            for name in self.file_names:
                print(name)
        except FileNotFoundError:
            self.root.after(0, lambda: self.status_label.config(text="Error: File names file not found."))
            logging.error("Error: File names file not found.")
        except IOError as e:
            self.root.after(0, lambda: self.status_label.config(text=f"Error reading file names file: {str(e)}"))
            logging.error(f"Error reading file names file: {str(e)}")
        except Exception as e:
            self.root.after(0, lambda: self.status_label.config(text=f"Error refreshing file names: {str(e)}"))
            logging.error(f"Error refreshing file names: {str(e)}")

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
        
        # Reset time tracking
        self.start_time = 0
        self.last_update_time = 0
        self.processing_rate = 0
        
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
        if hasattr(self, 'main_frame'):
            self.main_frame.configure(
                bg=scheme['frame_bg'],
                highlightbackground=scheme['border']
            )

            # Update all widgets in main frame
            for widget in self.main_frame.winfo_children():
                if isinstance(widget, tk.Label):
                    widget.configure(bg=scheme['frame_bg'], fg=scheme['fg'])
                elif isinstance(widget, tk.Entry):
                    widget.configure(
                        bg=scheme['entry_bg'],
                        fg=scheme['fg'],
                        insertbackground=scheme['fg']
                    )
                elif isinstance(widget, tk.Button):
                    widget.configure(bg=scheme['button_bg'], fg=scheme['fg'])
                elif isinstance(widget, tk.Text):
                    widget.configure(
                        bg=scheme['entry_bg'],
                        fg=scheme['fg'],
                        insertbackground=scheme['fg']
                    )
                elif isinstance(widget, tk.Frame):
                    widget.configure(bg=scheme['frame_bg'])
                    # Update widgets inside frames
                    for child in widget.winfo_children():
                        if isinstance(child, tk.Button):
                            child.configure(bg=scheme['button_bg'], fg=scheme['fg'])

        # Update progress bar style if it exists
        if hasattr(self, 'progress_bar'):
            style = ttk.Style()
            style.configure(
                "Custom.Horizontal.TProgressbar",
                background=scheme['button_bg'],
                troughcolor=scheme['entry_bg']
            )
            self.progress_bar.configure(style="Custom.Horizontal.TProgressbar")

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
        """Apply color scheme to tutorial or help window."""
        scheme = self.dark_scheme if self.is_dark_mode else self.light_scheme
        
        # Configure window background
        window.configure(bg=scheme['bg'])
        
        # Update all widgets in the window
        for widget in window.winfo_children():
            if isinstance(widget, tk.Frame):
                widget.configure(bg=scheme['frame_bg'])
                # Update widgets inside frames
                for child in widget.winfo_children():
                    if isinstance(child, tk.Label):
                        child.configure(bg=scheme['frame_bg'], fg=scheme['fg'])
                    elif isinstance(child, tk.Text):
                        child.configure(
                            bg=scheme['entry_bg'],
                            fg=scheme['fg'],
                            insertbackground=scheme['fg']
                        )
                    elif isinstance(child, tk.Button):
                        child.configure(bg=scheme['button_bg'], fg=scheme['fg'])
                    elif isinstance(child, tk.Frame):
                        child.configure(bg=scheme['frame_bg'])
                        # Update widgets inside nested frames
                        for grandchild in child.winfo_children():
                            if isinstance(grandchild, tk.Text):
                                grandchild.configure(
                                    bg=scheme['entry_bg'],
                                    fg=scheme['fg'],
                                    insertbackground=scheme['fg']
                                )
                            elif isinstance(grandchild, tk.Scrollbar):
                                grandchild.configure(
                                    bg=scheme['button_bg'],
                                    troughcolor=scheme['entry_bg']
                                )

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

if __name__ == "__main__":
    root = TkinterDnD.Tk()  # Use TkinterDnD instead of regular Tk
    app = HashVettingApp(root)
    root.mainloop()
