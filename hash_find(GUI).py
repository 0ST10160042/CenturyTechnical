import tkinter as tk
from tkinter import filedialog, ttk
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

# Constants
HASH_FILE_PATH = r"C:\Users\abelw\OneDrive\Documents\Hash_Test.txt"
TARGET_FOLDER = r"C:\Users\abelw\OneDrive\Documents\TESTING_HASH"
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
    
    # Initialize progress bar
    progress = tqdm(total=file_count, desc="Processing files", unit="file")

    for file_path in Path(directory).rglob('*'):
        if file_path.is_file():
            total_files_processed += 1
            progress.update(1)
            
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

    progress.close()

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

class HashVettingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Hash Vetting App")
        
        # Input fields
        self.hash_file_label = tk.Label(root, text="Hash File:")
        self.hash_file_label.grid(row=0, column=0)
        self.hash_file_entry = tk.Entry(root, width=50)
        self.hash_file_entry.grid(row=0, column=1)
        self.browse_hash_button = tk.Button(root, text="Browse", command=self.browse_hash_file)
        self.browse_hash_button.grid(row=0, column=2)
        
        self.target_folder_label = tk.Label(root, text="Target Folder:")
        self.target_folder_label.grid(row=1, column=0)
        self.target_folder_entry = tk.Entry(root, width=50)
        self.target_folder_entry.grid(row=1, column=1)
        self.browse_target_button = tk.Button(root, text="Browse", command=self.browse_target_folder)
        self.browse_target_button.grid(row=1, column=2)
        
        self.script_folder_label = tk.Label(root, text="Script Folder:")
        self.script_folder_label.grid(row=2, column=0)
        self.script_folder_entry = tk.Entry(root, width=50)
        self.script_folder_entry.grid(row=2, column=1)
        self.browse_script_button = tk.Button(root, text="Browse", command=self.browse_script_folder)
        self.browse_script_button.grid(row=2, column=2)
        
        self.quarantine_folder_label = tk.Label(root, text="Quarantine Folder:")
        self.quarantine_folder_label.grid(row=3, column=0)
        self.quarantine_folder_entry = tk.Entry(root, width=50)
        self.quarantine_folder_entry.grid(row=3, column=1)
        self.browse_quarantine_button = tk.Button(root, text="Browse", command=self.browse_quarantine_folder)
        self.browse_quarantine_button.grid(row=3, column=2)
        
        # Buttons
        self.button_frame = tk.Frame(root)
        self.button_frame.grid(row=4, column=0, columnspan=3)
        self.load_hashes_button = tk.Button(self.button_frame, text="Load Hashes", command=self.load_hashes)
        self.load_hashes_button.pack(side=tk.LEFT)
        self.report_button = tk.Button(self.button_frame, text="Generate Report", command=self.generate_report)
        self.report_button.pack(side=tk.LEFT)
        
        self.scan_button = tk.Button(root, text="Scan and Move", bg='blue', fg='white', height=2, width=20, command=self.scan_and_move)
        self.scan_button.grid(row=5, column=0, columnspan=3, sticky='ew')
        
        self.status_label = tk.Label(root, text="Status: Idle")
        self.status_label.grid(row=6, column=0, columnspan=3)
        
        self.progress_bar = ttk.Progressbar(root, orient='horizontal', length=400, mode='determinate')
        self.progress_bar.grid(row=7, column=0, columnspan=3)
        
    def load_hashes(self):
        # Load hashes from file
        hash_file_path = self.hash_file_entry.get()
        self.input_hashes = load_hashes_from_file(hash_file_path)
        self.status_label['text'] = f"Loaded {len(self.input_hashes)} hashes"
        print("Loaded hashes:")
        for h in self.input_hashes:
            print(h)
    
    def scan_and_move(self):
        # Scan and move files
        target_folder_path = self.target_folder_entry.get()
        self.status_label['text'] = "Scanning..."
        self.progress_bar['value'] = 0
        find_and_compare_hashes(Path(target_folder_path), self.input_hashes)
        self.status_label['text'] = "Scan complete."
        
        # Display removed files folder
        os.startfile(self.quarantine_folder_entry.get())
        
        # Open generated report
        os.startfile('matches_report.txt')
    
    def generate_report(self):
        # Generate report
        self.status_label['text'] = "Generating report..."
        # Add report generation logic here if needed
        
    def browse_hash_file(self):
        file_path = filedialog.askopenfilename(title="Select Hash File")
        self.hash_file_entry.delete(0, tk.END)
        self.hash_file_entry.insert(0, file_path)
    
    def browse_target_folder(self):
        folder_path = filedialog.askdirectory(title="Select Target Folder")
        self.target_folder_entry.delete(0, tk.END)
        self.target_folder_entry.insert(0, folder_path)

    def browse_script_folder(self):
        folder_path = filedialog.askdirectory(title="Select Script Folder")
        self.script_folder_entry.delete(0, tk.END)

    def browse_quarantine_folder(self):
        folder_path = filedialog.askdirectory(title="Select Quarantine Folder")
        self.quarantine_folder_entry.delete(0, tk.END)
        self.quarantine_folder_entry.insert(0, folder_path)

if __name__ == "__main__":
    root = tk.Tk()
    app = HashVettingApp(root)
    root.mainloop()


