import tkinter as tk
from tkinter import filedialog, ttk, messagebox
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

# Constants
HASH_FILE_PATH = r"C:\Users\abelw\OneDrive\Documents\Discovery_Hashes.txt"
TARGET_FOLDER = r"D:\Discovery_Search_Results_Final_Batch_2"
SCRIPT_FOLDER = r"C:\Users\abelw\OneDrive\Documents\hashScript"
QUARANTINE_FOLDER = r"C:\Users\abelw\OneDrive\Documents\hashScript\\Removed_files"

# Configure logging
logging.basicConfig(
    filename='duplicate_report.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def load_hashes_from_file(file_path):
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
            if file_path.suffix in ['.pst', '.ost', '.mbox', '.eml', '.emlx']:
                logging.error(f"Cannot move archived email file: {file_path}")
                return None, f"Cannot move archived email file: {file_path}"
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

def find_and_compare_hashes(directory, input_hashes, progress_bar, progress_bar_label, root, file_names=None, algorithms=['md5', 'sha1']):
    """Core processing with progress visualization"""
    file_hashes = {}
    matches = []
    moved_files_info = []
    failed_moves = []
    failed_scans = []
    total_files_processed = 0

    print(f"Scanning directory: {directory} using algorithms: {', '.join(algorithms)}")
    
    # Ensure quarantine folder exists
    Path(QUARANTINE_FOLDER).mkdir(parents=True, exist_ok=True)

    # Get total file count for progress bar
    file_count = sum(1 for _ in Path(directory).rglob('*') if _.is_file())
    
    # Set the maximum value for the progress bar
    progress_bar['maximum'] = file_count

    for file_path in Path(directory).rglob('*'):
        if file_path.is_file():
            total_files_processed += 1
            progress_bar['value'] = total_files_processed
            progress_percentage = (total_files_processed / file_count) * 100
            root.after(0, lambda: progress_bar.config(value=total_files_processed))
            root.after(0, lambda: progress_bar_label.config(text=f"Progress: {progress_percentage:.2f}%"))
            
            try:
                # Check if file name matches
                if file_names and file_path.name in file_names:
                    matches.append((file_path, 'N/A', 'File Name'))
                    new_path, error = secure_move(file_path)
                    if new_path:
                        moved_files_info.append((file_path, new_path, 'N/A', 'File Name'))
                    else:
                        failed_moves.append((file_path, 'N/A', 'File Name', error))
                    continue

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

    # Display removed files folder
    os.startfile(QUARANTINE_FOLDER)

    # Open generated report
    os.startfile('matches_report.txt')

    return matches, moved_files_info

class HashVettingApp:

    def browse_hash_file(self):
        file_path = filedialog.askopenfilename(title="Select Hash File")
        print(f"Debug: Selected file path: {file_path}")  # Debugging: Print the selected file path
        if file_path:
            try:
                # Open the file in read mode
                with open(file_path, 'r') as file:
                    pass
            except IOError:
                messagebox.showinfo("Notice", "Please ensure the file is saved and closed before loading.")
                self.status_label.config(text="Error: File is open in another program.")
                return
            
            self.hash_file_entry.delete(0, tk.END)
            self.hash_file_entry.insert(0, file_path)
            self.status_label.config(text=f"Loaded hash file: {file_path}")  # Update status label
            print(f"Debug: File path set in entry: {file_path}")  # Debugging: Print the file path set in the entry

    def __init__(self, root):
        self.root = root
        self.root.title("OPTIMUS-VET")
        self.root.configure(bg='#2e2e2e')  # Dark gray background

        # Configure grid weights for the root
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Main frame with increased outer padding and thicker, lighter border
        main_frame = tk.Frame(root, bg='#2e2e2e', highlightbackground='#6e6e6e', highlightthickness=4)
        main_frame.grid(row=0, column=0, padx=20, pady=20, sticky='nsew')  # Increased outer padding

        # Configure grid weights for main_frame
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_rowconfigure(2, weight=1)
        main_frame.grid_rowconfigure(3, weight=1)
        main_frame.grid_rowconfigure(4, weight=1)
        main_frame.grid_rowconfigure(5, weight=1)
        main_frame.grid_rowconfigure(6, weight=1)
        main_frame.grid_rowconfigure(7, weight=1)
        main_frame.grid_rowconfigure(8, weight=1)
        main_frame.grid_rowconfigure(9, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        main_frame.grid_columnconfigure(2, weight=1)

        # Input fields with reduced width
        self.hash_file_label = tk.Label(main_frame, text="Hash File:", bg='#2e2e2e', fg='white', bd=2, relief='groove')
        self.hash_file_label.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)
        self.hash_file_entry = tk.Entry(main_frame, width=30, bg='#3e3e3e', fg='white', insertbackground='white', bd=2, relief='groove')
        self.hash_file_entry.grid(row=0, column=1, sticky='nsew', padx=5, pady=5)
        self.browse_hash_button = tk.Button(main_frame, text="Browse", command=self.browse_hash_file, bg='#4e4e4e', fg='white', bd=2, relief='flat', height=1)
        self.browse_hash_button.grid(row=0, column=2, sticky='nsew', padx=5, pady=5)
        
        # Input fields for file names
        self.file_names_label = tk.Label(main_frame, text="File Names File:", bg='#2e2e2e', fg='white', bd=2, relief='groove')
        self.file_names_label.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)
        self.file_names_entry = tk.Entry(main_frame, width=30, bg='#3e3e3e', fg='white', insertbackground='white', bd=2, relief='groove')
        self.file_names_entry.grid(row=1, column=1, sticky='nsew', padx=5, pady=5)
        self.browse_file_names_button = tk.Button(main_frame, text="Browse", command=self.browse_file_names_file, bg='#4e4e4e', fg='white', bd=2, relief='flat', height=1)
        self.browse_file_names_button.grid(row=1, column=2, sticky='nsew', padx=5, pady=5)
        
        # Adjust the positions of the existing elements
        self.target_folder_label = tk.Label(main_frame, text="Source Folder:", bg='#2e2e2e', fg='white', bd=2, relief='groove')
        self.target_folder_label.grid(row=2, column=0, sticky='nsew', padx=5, pady=5)
        self.target_folder_entry = tk.Entry(main_frame, width=30, bg='#3e3e3e', fg='white', insertbackground='white', bd=2, relief='groove')
        self.target_folder_entry.grid(row=2, column=1, sticky='nsew', padx=5, pady=5)
        self.browse_target_button = tk.Button(main_frame, text="Browse", command=self.browse_target_folder, bg='#4e4e4e', fg='white', bd=2, relief='flat', height=1)
        self.browse_target_button.grid(row=2, column=2, sticky='nsew', padx=5, pady=5)
        
        self.quarantine_folder_label = tk.Label(main_frame, text="Destination Folder:", bg='#2e2e2e', fg='white', bd=2, relief='groove')
        self.quarantine_folder_label.grid(row=3, column=0, sticky='nsew', padx=5, pady=5)
        self.quarantine_folder_entry = tk.Entry(main_frame, width=30, bg='#3e3e3e', fg='white', insertbackground='white', bd=2, relief='groove')
        self.quarantine_folder_entry.grid(row=3, column=1, sticky='nsew', padx=5, pady=5)
        self.browse_quarantine_button = tk.Button(main_frame, text="Browse", command=self.browse_quarantine_folder, bg='#4e4e4e', fg='white', bd=2, relief='flat', height=1)
        self.browse_quarantine_button.grid(row=3, column=2, sticky='nsew', padx=5, pady=5)
        
        # Buttons with reduced height and modern look
        self.button_frame = tk.Frame(main_frame, bg='#2e2e2e')
        self.button_frame.grid(row=4, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        self.load_button = tk.Button(self.button_frame, text="Load Hashes/File Names", command=self.load_data, bg='#4e4e4e', fg='white', bd=2, relief='flat', height=1, padx=10, pady=5)
        self.load_button.pack(side=tk.LEFT, expand=True, fill='x', padx=3, pady=2)
        
        self.refresh_data_button = tk.Button(self.button_frame, text="Refresh Hashes/File Names", command=self.refresh_data, bg='#4e4e4e', fg='white', bd=2, relief='flat', height=1, padx=10, pady=5)
        self.refresh_data_button.pack(side=tk.LEFT, expand=True, fill='x', padx=3, pady=2)

        self.refresh_gui_button = tk.Button(self.button_frame, text="Refresh", command=self.refresh_app, bg='#4e4e4e', fg='white', bd=2, relief='flat', height=1, padx=10, pady=5)
        self.refresh_gui_button.pack(side=tk.LEFT, expand=True, fill='x', padx=3, pady=2)
        
        self.scan_button = tk.Button(main_frame, text="Scan and Move", bg='#4e4e4e', fg='white', height=1, width=10, command=self.scan_and_move, bd=2, relief='flat', padx=10, pady=5)
        self.scan_button.grid(row=5, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        
        self.progress_bar = ttk.Progressbar(main_frame, orient='horizontal', length=400, mode='determinate')
        self.progress_bar.grid(row=6, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        
        # Add a label for displaying progress percentage
        self.progress_bar_label = tk.Label(main_frame, text="Progress: 0%", bg='#2e2e2e', fg='white', bd=2, relief='groove')
        self.progress_bar_label.grid(row=7, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        
        self.status_label = tk.Label(main_frame, text="Status: Idle", bg='#2e2e2e', fg='white', bd=2, relief='groove', wraplength=400)
        self.status_label.grid(row=8, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        
        # Add a Text widget for displaying invalid hashes
        self.invalid_hashes_text = tk.Text(main_frame, height=5, bg='#3e3e3e', fg='white', wrap='word')
        self.invalid_hashes_text.grid(row=9, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        
    def load_data(self):
        """Load hashes and file names from their respective files."""
        self.load_hashes()
        self.load_file_names()

    def refresh_data(self):
        """Refresh hashes and file names from their respective files."""
        self.refresh_hashes()
        self.refresh_file_names()

    def load_hashes(self):
        # Load hashes from file
        hash_file_path = self.hash_file_entry.get()
        print(f"Debug: Retrieved file path from entry: {hash_file_path}")  # Debugging: Print the file path being retrieved
        if not os.path.isfile(hash_file_path):
            self.status_label.config(text="Error: Hash file does not exist or is not saved.")
            print(f"Debug: File does not exist or is not saved: {hash_file_path}")  # Debugging: Print error message with file path
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
                self.status_label['text'] = f"Loaded {len(self.input_hashes)} valid hashes. Warning: {len(invalid_hashes)} invalid hashes and {duplicates_count} duplicates were skipped."
                self.invalid_hashes_text.delete('1.0', tk.END)
                self.invalid_hashes_text.insert(tk.END, f"Invalid hashes: {invalid_hashes_str}")
                print(f"Invalid hashes: {invalid_hashes_str}")  # Debugging: Print invalid hashes
            else:
                self.status_label['text'] = f"Loaded {len(self.input_hashes)} valid hashes"
                self.invalid_hashes_text.delete('1.0', tk.END)
            print("Loaded hashes:")
            for h in self.input_hashes:
                print(h)
            print("Debug: Hashes loaded successfully.")  # Debugging: Confirm successful loading
        except Exception as e:
            self.status_label['text'] = f"Error loading hashes: {str(e)}"
            logging.error(f"Error loading hashes: {str(e)}")
            print(f"Debug: Error loading hashes: {str(e)}")  # Debugging: Print exception message
            raise  # Re-raise the exception to see the full traceback in the console
    
    def scan_and_move(self):
        # Ensure hashes or file names are loaded
        if not hasattr(self, 'input_hashes') and not hasattr(self, 'file_names'):
            self.status_label['text'] = "Error: No hashes or file names loaded."
            print("Error: No hashes or file names loaded.")
            return

        # Scan and move files in a separate thread to keep the GUI responsive
        target_folder_path = self.target_folder_entry.get()
        self.status_label['text'] = "Scanning..."
        self.progress_bar['value'] = 0

        # Start a new thread for scanning and moving files
        scan_thread = threading.Thread(target=self.run_scan_and_move, args=(target_folder_path,))
        scan_thread.start()

    def run_scan_and_move(self, target_folder_path):
        self.status_label['text'] = "Scanning..."
        matches, moved_files_info = find_and_compare_hashes(Path(target_folder_path), self.input_hashes, self.progress_bar, self.progress_bar_label, self.root, self.file_names)
        self.status_label['text'] = "Scan complete."
        root.after(0, lambda: self.progress_bar_label.config(text="Progress: Complete"))

        # Generate Excel report
        self.generate_excel_report(moved_files_info)

        # Ensure the match report is opened
        os.startfile('matches_report.txt')
    
    def generate_report(self):
        # Generate report
        self.status_label['text'] = "Generating report..."
        # Add report generation logic here if needed
        
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
        if not os.path.isfile(hash_file_path):
            self.status_label.config(text="Error: Hash file does not exist or is not saved.")
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
                self.status_label['text'] = f"Refreshed: {len(self.input_hashes)} valid hashes loaded with {duplicates_count} duplicates removed."
                self.invalid_hashes_text.delete('1.0', tk.END)
                self.invalid_hashes_text.insert(tk.END, f"Invalid hashes: {invalid_hashes_str}")
                print(f"Invalid hashes: {invalid_hashes_str}")  # Debugging: Print invalid hashes
            else:
                self.status_label['text'] = f"Refreshed: {len(self.input_hashes)} valid hashes loaded"
                self.invalid_hashes_text.delete('1.0', tk.END)
            print("Refreshed hashes:")
            for h in self.input_hashes:
                print(h)
        except Exception as e:
            self.status_label['text'] = f"Error refreshing hashes: {str(e)}"
            logging.error(f"Error refreshing hashes: {str(e)}")

    def browse_file_names_file(self):
        file_path = filedialog.askopenfilename(title="Select File Names File")
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    self.file_names = {line.strip() for line in file if line.strip()}
                self.file_names_entry.delete(0, tk.END)
                self.file_names_entry.insert(0, file_path)
                self.status_label.config(text=f"Loaded {len(self.file_names)} file names.")
            except Exception as e:
                self.status_label.config(text=f"Error loading file names: {str(e)}")
                logging.error(f"Error loading file names: {str(e)}")

    def generate_excel_report(self, moved_files_info):
        df = pd.DataFrame(moved_files_info, columns=['Original Path', 'New Path', 'Hash', 'Algorithm'])
        df['File Name'] = df['Original Path'].apply(lambda x: Path(x).name)
        df.to_excel('moved_files_report.xlsx', index=False)
        print("Excel report generated: moved_files_report.xlsx")

    def load_file_names(self):
        """Load file names from file."""
        file_names_file_path = self.file_names_entry.get()
        if not os.path.isfile(file_names_file_path):
            self.status_label.config(text="Error: File names file does not exist or is not saved.")
            return
        try:
            # Read lines from the file
            with open(file_names_file_path, 'r') as file:
                self.file_names = {line.strip() for line in file if line.strip()}
            self.status_label['text'] = f"Loaded {len(self.file_names)} file names."
            print("Loaded file names:")
            for name in self.file_names:
                print(name)
        except Exception as e:
            self.status_label['text'] = f"Error loading file names: {str(e)}"
            logging.error(f"Error loading file names: {str(e)}")

    def refresh_file_names(self):
        """Refresh the loaded file names from the file."""
        file_names_file_path = self.file_names_entry.get()
        if not os.path.isfile(file_names_file_path):
            self.status_label.config(text="Error: File names file does not exist or is not saved.")
            return
        try:
            # Read lines from the file
            with open(file_names_file_path, 'r') as file:
                self.file_names = {line.strip() for line in file if line.strip()}
            self.status_label['text'] = f"Refreshed: {len(self.file_names)} file names loaded."
            print("Refreshed file names:")
            for name in self.file_names:
                print(name)
        except Exception as e:
            self.status_label['text'] = f"Error refreshing file names: {str(e)}"
            logging.error(f"Error refreshing file names: {str(e)}")

    def refresh_app(self):
        """Refresh the application to its initial state."""
        self.hash_file_entry.delete(0, tk.END)
        self.file_names_entry.delete(0, tk.END)
        self.target_folder_entry.delete(0, tk.END)
        self.quarantine_folder_entry.delete(0, tk.END)
        self.status_label['text'] = "Status: Idle"
        self.progress_bar['value'] = 0
        self.input_hashes = set()
        self.file_names = set()
        self.invalid_hashes_text.delete('1.0', tk.END)
        print("Application refreshed.")

if __name__ == "__main__":
    root = tk.Tk()
    app = HashVettingApp(root)
    root.mainloop()
