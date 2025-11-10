"""
Simple terminal password manager (single-file).
Created by Ream Daly.
Project : Vanessa Kang
Date : 10/23/2025

Features implemented:
- Master password creation (asks twice to verify) and strength checking
- Master password stored as salted PBKDF2-HMAC-SHA256 hash in 'master.hash'
- Vault (website -> password) stored encrypted in 'vault.bin' using Fernet with key derived from master password
- CRUD operations: Create (user-provided or generated password), Read (search/filter, list), Update, Delete
- Every sensitive action (view, update, delete) requires entering the master password (hidden with getpass)
- Logs user actions (timestamp, action, website) in 'actions.log' (plaintext; doesn't store passwords)
- Program loops until the user exits

Dependencies:
- cryptography (install with: pip install cryptography)

Run:
python VanessaKang.py

Note: keep files in same directory: master.hash, vault.bin, actions.log
"""

import os
import json
import sys
import base64
import secrets
import string
import datetime
import msvcrt
import time
import shutil
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Try to import pyperclip for clipboard functionality
try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except Exception as e:
    print("This program requires the 'cryptography' package. Install it with: pip install cryptography")
    sys.exit(1)

MASTER_HASH_FILE = 'master.hash'
VAULT_FILE = 'vault.bin'
LOG_FILE = 'actions.log'
BACKUP_DIR = r'D:\Dump\pastion'
BACKUP_SUBDIRS = {
    'master': 'master',
    'vault': 'vaults',
    'actions': 'actions'
}
TIMEOUT_SECONDS = 90 * 60  # 90 minutes in seconds
MAX_BACKUPS = 20  # Keep last 20 backups

# ANSI Color codes for beautiful output
CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
GRAY = '\033[90m'
BOLD = '\033[1m'
DIM = '\033[2m'
REVERSE = '\033[7m'
RESET = '\033[0m'

# Global variable to track last activity time
last_activity_time = time.time()


def print_header(text, color=CYAN):
    """Print a centered header with decorative borders."""
    try:
        terminal_width = os.get_terminal_size().columns
    except:
        terminal_width = 80
    
    text_len = len(text)
    padding = (terminal_width - text_len - 4) // 2
    border = '═' * (terminal_width - 4)
    
    print(f'\n{color}╔{border}╗{RESET}')
    print(f'{color}║{" " * padding}{BOLD}{text}{RESET}{color}{" " * (terminal_width - text_len - padding - 4)}║{RESET}')
    print(f'{color}╚{border}╝{RESET}\n')


def print_info(label, value, color=CYAN):
    """Print information in a formatted way."""
    if value:
        print(f'{GRAY}  ▸ {RESET}{BOLD}{label}:{RESET} {color}{value}{RESET}')


def print_success(message):
    """Print a success message."""
    print(f'{GREEN}✓ {message}{RESET}')


def print_error(message):
    """Print an error message."""
    print(f'{RED}✗ {message}{RESET}')


def print_warning(message):
    """Print a warning message."""
    print(f'{YELLOW}⚠ {message}{RESET}')


def update_activity_time():
    """Update the last activity timestamp."""
    global last_activity_time
    last_activity_time = time.time()


def check_timeout():
    """Check if the program has been inactive for too long."""
    global last_activity_time
    elapsed = time.time() - last_activity_time
    if elapsed >= TIMEOUT_SECONDS:
        print('Session timed out due to inactivity (90 minutes). Exiting for security.')
        sys.exit(0)


def cleanup_old_backups():
    """Keep only the most recent MAX_BACKUPS versions of each file in their subfolders."""
    try:
        if not os.path.exists(BACKUP_DIR):
            return
        
        # Mapping of files to their subfolders
        file_mapping = {
            MASTER_HASH_FILE: BACKUP_SUBDIRS['master'],
            VAULT_FILE: BACKUP_SUBDIRS['vault'],
            LOG_FILE: BACKUP_SUBDIRS['actions']
        }
        
        # For each file type, keep only the latest MAX_BACKUPS versions in their subfolder
        for base_filename, subfolder in file_mapping.items():
            subdir_path = os.path.join(BACKUP_DIR, subfolder)
            if not os.path.exists(subdir_path):
                continue
            
            # Get all timestamped backups for this file
            base_name = os.path.splitext(base_filename)[0]
            extension = os.path.splitext(base_filename)[1]
            
            backup_files = []
            
            for file in os.listdir(subdir_path):
                if file.startswith(base_name + "_") and file.endswith(extension):
                    file_path = os.path.join(subdir_path, file)
                    try:
                        backup_files.append((file_path, os.path.getmtime(file_path)))
                    except:
                        pass
            
            # Sort by modification time (newest first)
            backup_files.sort(key=lambda x: x[1], reverse=True)
            
            # Delete old backups beyond MAX_BACKUPS
            for file_path, _ in backup_files[MAX_BACKUPS:]:
                try:
                    os.remove(file_path)
                except:
                    pass
    except:
        pass


def backup_files():
    """Backup master.hash, vault.bin, and actions.log into their respective subfolders with timestamps."""
    try:
        # Create backup directory and subfolders if they don't exist
        os.makedirs(BACKUP_DIR, exist_ok=True)
        for subfolder in BACKUP_SUBDIRS.values():
            os.makedirs(os.path.join(BACKUP_DIR, subfolder), exist_ok=True)
        
        # Create timestamp for backup files
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        
        # Mapping of files to their subfolders
        file_mapping = {
            MASTER_HASH_FILE: BACKUP_SUBDIRS['master'],
            VAULT_FILE: BACKUP_SUBDIRS['vault'],
            LOG_FILE: BACKUP_SUBDIRS['actions']
        }
        
        # Backup each file if it exists with timestamp
        for filename, subfolder in file_mapping.items():
            if os.path.exists(filename):
                # Create timestamped backup filename
                base_name = os.path.splitext(filename)[0]
                extension = os.path.splitext(filename)[1]
                backup_filename = f"{base_name}_{timestamp}{extension}"
                
                # Get subfolder path
                subdir_path = os.path.join(BACKUP_DIR, subfolder)
                backup_path = os.path.join(subdir_path, backup_filename)
                
                # Copy file to timestamped backup in subfolder
                shutil.copy2(filename, backup_path)
                
                # Also keep a "latest" copy without timestamp in the same subfolder
                latest_backup_path = os.path.join(subdir_path, filename)
                shutil.copy2(filename, latest_backup_path)
        
        # Cleanup old backups to save space
        cleanup_old_backups()
        
    except Exception as e:
        # Silently fail - don't interrupt user operations
        pass

def write_log(action, website=None):
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    entry = f"{ts} | {action}"
    if website:
        entry += f" | {website}"
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(entry + '\n')
    backup_files()  # Backup after writing to log


def pretty_input(prompt):
    try:
        check_timeout()  # Check for timeout before getting input
        result = input(prompt)
        update_activity_time()  # Update activity time after input
        return result
    except (KeyboardInterrupt, EOFError):
        print('Exiting...')
        sys.exit(0)


def masked_input(prompt):
    """Get input from user and display asterisks (*) for each character typed."""
    check_timeout()  # Check for timeout before getting input
    print(prompt, end='', flush=True)
    password = ''
    while True:
        char = msvcrt.getch()
        
        # Enter key (carriage return)
        if char in (b'\r', b'\n'):
            print()
            break
        # Backspace
        elif char == b'\x08':
            if len(password) > 0:
                password = password[:-1]
                # Move cursor back, print space, move back again
                print('\b \b', end='', flush=True)
        # Ctrl+C
        elif char == b'\x03':
            print()
            raise KeyboardInterrupt
        # Normal character
        else:
            try:
                password += char.decode('utf-8')
                print('*', end='', flush=True)
            except:
                pass
    
    update_activity_time()  # Update activity time after input
    return password


def interactive_menu():
    """Display an interactive menu with arrow key navigation and colored selection.
    Returns the selected option number as a string.
    """
    check_timeout()  # Check for timeout
    
    # ANSI color codes
    CLEAR_SCREEN = '\033[2J\033[H'
    RESET = '\033[0m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    REVERSE = '\033[7m'
    DIM = '\033[2m'
    
    # Menu options with descriptions
    options = [
        ('1', 'Create entry', 'Add new credential'),
        ('2', 'Read / View entry', 'Search and view credentials'),
        ('3', 'Update entry', 'Modify existing entry'),
        ('4', 'Delete entry', 'Remove entry permanently'),
        ('5', 'List all websites', 'Display all entries'),
        ('6', 'View action log', 'Show action history'),
        ('7', 'Clear action log', 'Remove old log entries'),
        ('8', 'Restore from backup', 'Restore from backup files'),
        ('9', 'Change master password', 'Update master password'),
        ('c', 'Clear', 'Clear this terminal session'),
        ('a', 'About', 'About this program'),
        ('0', 'Exit', 'Close application'),
    ]
    
    selected_idx = 0
    total_options = len(options)
    
    while True:
        # Clear screen and render menu
        print(CLEAR_SCREEN, end='')
        
        # Title - Always show full logo
        print(f'{CYAN}')
        print('  ██╗   ██╗ █████╗ ███╗   ██╗███████╗███████╗███████╗ █████╗     ██╗  ██╗ █████╗ ███╗   ██╗ ██████╗ ')
        print('  ██║   ██║██╔══██╗████╗  ██║██╔════╝██╔════╝██╔════╝██╔══██╗    ██║ ██╔╝██╔══██╗████╗  ██║██╔════╝ ')
        print('  ██║   ██║███████║██╔██╗ ██║█████╗  ███████╗███████╗███████║    █████╔╝ ███████║██╔██╗ ██║██║  ███╗')
        print('  ╚██╗ ██╔╝██╔══██║██║╚██╗██║██╔══╝  ╚════██║╚════██║██╔══██║    ██╔═██╗ ██╔══██║██║╚██╗██║██║   ██║')
        print('   ╚████╔╝ ██║  ██║██║ ╚████║███████╗███████║███████║██║  ██║    ██║  ██╗██║  ██║██║ ╚████║╚██████╔╝')
        print('    ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ')
        print(f'{RESET}\n')
        
        # Display options
        for idx, (num, label, description) in enumerate(options):
            if idx == selected_idx:
                # Highlighted option
                print(f'{REVERSE}{CYAN}  ► {label:<25}{RESET}  {BOLD}{description}{RESET}')
            else:
                # Normal option
                print(f'{DIM}    {label:<25}{RESET}  {description}')
        
        print(f'\n{DIM}  ({total_options} options | Use ↑↓ arrows and Enter to select){RESET}')
        
        # Read arrow keys
        key = msvcrt.getch()
        
        if key == b'\xe0' or key == b'\x00':  # Arrow key prefix
            key = msvcrt.getch()
            if key == b'H':  # Up arrow
                selected_idx = (selected_idx - 1) % total_options
            elif key == b'P':  # Down arrow
                selected_idx = (selected_idx + 1) % total_options
        elif key == b'\r':  # Enter key
            update_activity_time()
            return options[selected_idx][0]
        elif key == b'\x1b':  # ESC key
            update_activity_time()
            return '0'
        elif key in (b'k', b'K'):  # Vim-style up
            selected_idx = (selected_idx - 1) % total_options
        elif key in (b'j', b'J'):  # Vim-style down
            selected_idx = (selected_idx + 1) % total_options
        # Ignore other keys


def input_box(prompt):
    """Display a modern input box with border like Gemini CLI.
    Returns the user input as a string.
    """
    check_timeout()
    
    # ANSI color codes
    CYAN = '\033[96m'
    RESET = '\033[0m'
    GRAY = '\033[90m'
    
    # Get terminal width
    try:
        terminal_width = os.get_terminal_size().columns
    except:
        terminal_width = 80
    
    # Calculate box width (responsive, leave margin)
    box_width = min(terminal_width - 10, 120)
    if box_width < 40:
        box_width = max(terminal_width - 4, 30)
    
    # Shorten prompt if too long to fit in box
    max_prompt_len = box_width - 6
    if len(prompt) > max_prompt_len:
        prompt = prompt[:max_prompt_len - 3] + '...'
    
    # Print complete box first
    print(f'\n{CYAN}╭{"─" * (box_width - 2)}╮{RESET}')
    print(f'{CYAN}│{" " * (box_width - 2)}│{RESET}')
    print(f'{CYAN}╰{"─" * (box_width - 2)}╯{RESET}')
    
    # Move cursor up 2 lines and position inside the box
    print('\033[2A', end='')  # Move up 2 lines
    print('\r', end='')  # Move to start of line
    print(f'{CYAN}│{RESET} {GRAY}{prompt}{RESET} ', end='', flush=True)
    
    # Get input using manual character reading
    user_input = ''
    cursor_pos = 2 + len(prompt) + 1  # Starting position after "│ prompt "
    
    while True:
        char = msvcrt.getch()
        
        # Enter key
        if char in (b'\r', b'\n'):
            # Move to next line after the box
            print('\r', end='')
            print('\033[2B', end='')  # Move down 2 lines
            print()
            break
        # Backspace
        elif char == b'\x08':
            if len(user_input) > 0:
                user_input = user_input[:-1]
                print('\b \b', end='', flush=True)
                cursor_pos -= 1
        # Ctrl+C
        elif char == b'\x03':
            print('\r', end='')
            print('\033[2B', end='')  # Move down 2 lines
            print()
            raise KeyboardInterrupt
        # Normal character
        else:
            try:
                decoded = char.decode('utf-8')
                # Check if we have space in the box
                if cursor_pos < box_width - 2:
                    user_input += decoded
                    print(decoded, end='', flush=True)
                    cursor_pos += 1
            except:
                pass
    
    update_activity_time()
    return user_input.strip()


def masked_input_box(prompt):
    """Display a modern input box with border and masked input (asterisks).
    Returns the user input as a string.
    """
    check_timeout()
    
    # ANSI color codes
    CYAN = '\033[96m'
    RESET = '\033[0m'
    GRAY = '\033[90m'
    
    # Get terminal width
    try:
        terminal_width = os.get_terminal_size().columns
    except:
        terminal_width = 80
    
    # Calculate box width (responsive, leave margin)
    box_width = min(terminal_width - 10, 120)
    if box_width < 40:
        box_width = max(terminal_width - 4, 30)
    
    # Shorten prompt if too long to fit in box
    max_prompt_len = box_width - 6
    if len(prompt) > max_prompt_len:
        prompt = prompt[:max_prompt_len - 3] + '...'
    
    # Print complete box first
    print(f'\n{CYAN}╭{"─" * (box_width - 2)}╮{RESET}')
    print(f'{CYAN}│{" " * (box_width - 2)}│{RESET}')
    print(f'{CYAN}╰{"─" * (box_width - 2)}╯{RESET}')
    
    # Move cursor up 2 lines and position inside the box
    print('\033[2A', end='')  # Move up 2 lines
    print('\r', end='')  # Move to start of line
    print(f'{CYAN}│{RESET} {GRAY}{prompt}{RESET} ', end='', flush=True)
    
    # Get masked input
    password = ''
    cursor_pos = 2 + len(prompt) + 1  # Starting position after "│ prompt "
    
    while True:
        char = msvcrt.getch()
        
        # Enter key
        if char in (b'\r', b'\n'):
            # Move to next line after the box
            print('\r', end='')
            print('\033[2B', end='')  # Move down 2 lines
            print()
            break
        # Backspace
        elif char == b'\x08':
            if len(password) > 0:
                password = password[:-1]
                print('\b \b', end='', flush=True)
                cursor_pos -= 1
        # Ctrl+C
        elif char == b'\x03':
            print('\r', end='')
            print('\033[2B', end='')  # Move down 2 lines
            print()
            raise KeyboardInterrupt
        # Normal character
        else:
            try:
                decoded = char.decode('utf-8')
                # Check if we have space in the box
                if cursor_pos < box_width - 2:
                    password += decoded
                    print('*', end='', flush=True)
                    cursor_pos += 1
            except:
                pass
    
    update_activity_time()
    return password


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def set_master_password():
    print(f'\n{YELLOW}No master password found. Let\'s create one!{RESET}')
    while True:
        pw1 = masked_input_box('New master password:')
        pw2 = masked_input_box('Repeat password:')
        if pw1 != pw2:
            print_error('Passwords do not match. Try again.')
            continue
        if not is_strong_password(pw1):
            print_error('Password not strong enough!')
            print(f'{GRAY}Requirements: at least 8 chars, upper, lower, digit, symbol.{RESET}')
            choice = input_box('Auto-generate password? (y/n):').strip().lower()
            if choice == 'y':
                suggested = generate_strong_password(16)
                print(f'\n{GREEN}Generated strong password:{RESET} {BOLD}{suggested}{RESET}')
                print(f'{YELLOW}⚠ Copy and save it somewhere safe!{RESET}')
                use = input_box('Use this password? (y/n):').strip().lower()
                if use == 'y':
                    pw1 = suggested
                else:
                    continue
            else:
                continue
        salt = secrets.token_bytes(16)
        key = derive_key(pw1.encode('utf-8'), salt)
        f = Fernet(key)
        token = f.encrypt(b'verify')
        with open(MASTER_HASH_FILE, 'wb') as fh:
            fh.write(salt + b'--' + token)
        empty = {}
        save_vault(empty, pw1)
        write_log('SET_MASTER')
        backup_files()  # Backup after setting master password
        print_success('Master password created and saved!')
        return

def load_master_salt_and_token():
    if not os.path.exists(MASTER_HASH_FILE):
        return None
    data = open(MASTER_HASH_FILE, 'rb').read()
    try:
        salt, token = data.split(b'--', 1)
        return salt, token
    except Exception:
        return None

def verify_master(password: str) -> bool:
    loaded = load_master_salt_and_token()
    if not loaded:
        return False
    salt, token = loaded
    try:
        key = derive_key(password.encode('utf-8'), salt)
        f = Fernet(key)
        dec = f.decrypt(token)
        return dec == b'verify'
    except Exception:
        return False

def load_vault(master_password: str):
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, 'rb') as f:
        data = f.read()
    try:
        vault_meta, token = data.split(b'--', 1)
        salt = vault_meta
        key = derive_key(master_password.encode('utf-8'), salt)
        fernet = Fernet(key)
        dec = fernet.decrypt(token)
        return json.loads(dec.decode('utf-8'))
    except Exception:
        raise ValueError('Unable to decrypt vault. Wrong master password or corrupted vault.')


def save_vault(vault_dict: dict, master_password: str):
    salt = secrets.token_bytes(16)
    key = derive_key(master_password.encode('utf-8'), salt)
    f = Fernet(key)
    data = json.dumps(vault_dict, ensure_ascii=False).encode('utf-8')
    token = f.encrypt(data)
    with open(VAULT_FILE, 'wb') as fh:
        fh.write(salt + b'--' + token)
    backup_files()  # Backup after saving vault


def is_strong_password(pw: str) -> bool:
    if len(pw) < 8:
        return False
    has_upper = any(c.isupper() for c in pw)
    has_lower = any(c.islower() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any((not c.isalnum()) for c in pw)
    return has_upper and has_lower and has_digit and has_symbol


def generate_strong_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        pw = ''.join(secrets.choice(alphabet) for _ in range(length))
        if is_strong_password(pw):
            return pw
        

def create_entry(vault):
    name = input_box('Website name:').strip()
    if not name:
        print_error('Website name cannot be empty.')
        return vault
    account = input_box('Account email (optional):').strip()
    if account and '@' not in account:
        print_warning('The email you entered does not look valid. Saving as entered.')
    
    # New optional fields
    username = input_box('Username (optional):').strip()
    phone_number = input_box('Phone number (optional):').strip()
    
    # Description field (max 30 words)
    description = input_box('Description (optional, max 30 words):').strip()
    if description:
        words = description.split()
        if len(words) > 30:
            description = ' '.join(words[:30])
            print_warning(f'Description truncated to 30 words.')
    
    print(f'\n{CYAN}Password Options:{RESET}')
    print(f'  {CYAN}1){RESET} Input your own password')
    print(f'  {CYAN}2){RESET} Generate a strong password')
    choice = input_box('Choose (1 or 2):').strip()
    if choice == '1':
        pw = masked_input_box('Enter password for %s:' % name)
    else:
        while True:
            length_s = input_box('Password length (8-16, default 16):').strip()
            if not length_s:
                length = 16
                break
            try:
                length = int(length_s)
            except Exception:
                print_error('Please enter a number between 8 and 16.')
                continue
            if length < 8 or length > 16:
                print_error('Length must be between 8 and 16. Try again.')
                continue
            break
        pw = generate_strong_password(length)
        print_success(f'Generated password: {GREEN}{pw}{RESET}')
    vault[name] = {
        'password': pw,
        'account': account,
        'username': username,
        'phone_number': phone_number,
        'description': description,
        'created': datetime.datetime.now().timestamp()
    }
    print_success('Entry saved successfully!')
    write_log('CREATE', name)
    return vault


def list_websites(vault):
    def _inner(max_items=None):
        if not vault:
            print_warning('No entries found.')
            return
        def _created_key(k):
            e = vault.get(k)
            if isinstance(e, dict):
                return e.get('created', 0)
            return 0
        keys = sorted(vault.keys(), key=_created_key, reverse=True)
        
        # Print header
        total = len(keys)
        if max_items:
            print_header(f'Stored Websites (Showing {min(max_items, total)} of {total})', CYAN)
        else:
            print_header(f'All Stored Websites ({total} entries)', CYAN)
        
        # Calculate column widths
        try:
            terminal_width = os.get_terminal_size().columns
        except:
            terminal_width = 120
        
        # Reserve space: "  99. " = 6 chars, then website name (30 chars), then description (rest)
        num_width = 6
        website_width = 35
        desc_start = num_width + website_width + 3  # 3 for " │ "
        max_desc_width = terminal_width - desc_start - 5
        
        if max_desc_width < 20:
            max_desc_width = 20
        
        # Print column headers
        print(f'  {BOLD}{CYAN}{"WEBSITE":<{website_width}}{RESET} {GRAY}│{RESET} {BOLD}{CYAN}DESCRIPTION{RESET}')
        print(f'  {GRAY}{"─" * website_width} ┼ {"─" * max_desc_width}{RESET}')
        
        to_show = keys if (max_items is None) else keys[:max_items]
        for i, k in enumerate(to_show, 1):
            # Get description
            entry = vault.get(k)
            if isinstance(entry, dict):
                desc = entry.get('description', '')
            else:
                desc = ''
            
            # Truncate description if too long
            if desc:
                if len(desc) > max_desc_width:
                    desc = desc[:max_desc_width - 3] + '...'
            else:
                desc = f'{GRAY}(no description){RESET}'
            
            # Truncate website name if too long
            display_name = k
            if len(k) > website_width - 5:
                display_name = k[:website_width - 8] + '...'
            
            # Print row
            print(f'  {CYAN}{i:2d}.{RESET} {BOLD}{display_name:<{website_width - 4}}{RESET} {GRAY}│{RESET} {desc}')
        
        if max_items is not None and len(keys) > max_items:
            print(f'\n  {GRAY}... and {len(keys) - max_items} more entries{RESET}')
        print()
    return _inner


def search_entries(vault, query):
    q = query.lower()
    matches = [k for k in vault.keys() if q in k.lower()]
    def _created_key(k):
        e = vault.get(k)
        if isinstance(e, dict):
            return e.get('created', 0)
        return 0
    return sorted(matches, key=_created_key, reverse=True)


def read_entry(vault):
    list_short = list_websites(vault)
    list_short(5)
    q = input_box('Website to search:').strip()
    matches = search_entries(vault, q)
    if not matches:
        print_warning('No matches found.')
        return
    if len(matches) == 1:
        chosen = matches[0]
    else:
        print(f'\n{CYAN}╔══════════════════════════════╗{RESET}')
        print(f'{CYAN}║{RESET}  {BOLD}Matching Entries{RESET}           {CYAN}║{RESET}')
        print(f'{CYAN}╚══════════════════════════════╝{RESET}\n')
        for idx, m in enumerate(matches, 1):
            print(f"  {CYAN}{idx}.{RESET} {m}")
        sel = input_box('Choose number or 0 to cancel:').strip()
        try:
            si = int(sel)
            if si == 0:
                return
            chosen = matches[si-1]
        except Exception:
            print_error('Invalid selection.')
            return
    mpw = masked_input_box('Enter master password:')
    if not verify_master(mpw):
        print('\nMaster password incorrect.')
        write_log('READ_FAILED', chosen)
        return
    entry = vault[chosen]
    if isinstance(entry, dict):
        pw = entry.get('password')
        acct = entry.get('account')
        username = entry.get('username')
        phone = entry.get('phone_number')
        desc = entry.get('description')
    else:
        pw = entry
        acct = None
        username = None
        phone = None
        desc = None
    
    # Display entry details in a beautiful format
    print_header(f'Entry Details: {chosen}', GREEN)
    print_info('Website', chosen, BOLD + CYAN)
    if acct:
        print_info('Account', acct, YELLOW)
    if username:
        print_info('Username', username, MAGENTA)
    if phone:
        print_info('Phone Number', phone, BLUE)
    if desc:
        print_info('Description', desc, GRAY)
    print_info('Password', pw, GREEN)
    print()
    
    # Copy password functionality
    if CLIPBOARD_AVAILABLE:
        copy_choice = input_box('Copy password to clipboard? (y/N):').strip().lower()
        if copy_choice == 'y':
            try:
                pyperclip.copy(pw)
                print_success('Password copied to clipboard!')
            except Exception as e:
                print_error(f'Failed to copy: {e}')
    else:
        print_warning('Install pyperclip to enable password copying (pip install pyperclip)')
    
    write_log('READ', chosen)


def update_entry(vault):
    if not vault:
        print_warning('No entries found.')
        return vault
    list_short = list_websites(vault)
    list_short(5)
    name = input_box('Website to update:').strip()
    matches = search_entries(vault, name)
    if not matches:
        print_warning('No matches found.')
        return vault
    if len(matches) == 1:
        chosen = matches[0]
    else:
        print(f'\n{YELLOW}Matching entries:{RESET}')
        for idx, m in enumerate(matches, 1):
            print(f"  {CYAN}{idx}.{RESET} {m}")
        sel = input_box('Choose number or 0 to cancel: ').strip()
        try:
            si = int(sel)
            if si == 0:
                return vault
            chosen = matches[si-1]
        except Exception:
            print_error('Invalid selection.')
            return vault
    
    # Interactive menu for update options
    update_options = [
        ('1', 'Change website name'),
        ('2', 'Change password'),
        ('3', 'Change account'),
        ('4', 'Change username'),
        ('5', 'Change phone number'),
        ('6', 'Change description'),
        ('0', 'Cancel'),
    ]
    
    selected_idx = 0
    total_options = len(update_options)
    
    while True:
        # Clear screen and show header
        print('\033[2J\033[H', end='')  # Clear screen
        print(f'\n{CYAN}╔══════════════════════════════════╗{RESET}')
        print(f'{CYAN}║{RESET}  {BOLD}What would you like to change?{RESET}  {CYAN}║{RESET}')
        print(f'{CYAN}╚══════════════════════════════════╝{RESET}\n')
        
        # Display options
        for idx, (num, label) in enumerate(update_options):
            if idx == selected_idx:
                # Highlighted option
                if num == '0':
                    print(f'  {REVERSE}{RED}► {label}{RESET}')
                else:
                    print(f'  {REVERSE}{CYAN}► {label}{RESET}')
            else:
                # Normal option
                if num == '0':
                    print(f'  {DIM}{RED}{label}{RESET}')
                else:
                    print(f'  {DIM}{label}{RESET}')
        
        print(f'\n{DIM}  (Use ↑↓ arrows and Enter to select){RESET}')
        
        # Read arrow keys
        key = msvcrt.getch()
        
        if key == b'\xe0' or key == b'\x00':  # Arrow key prefix
            key = msvcrt.getch()
            if key == b'H':  # Up arrow
                selected_idx = (selected_idx - 1) % total_options
            elif key == b'P':  # Down arrow
                selected_idx = (selected_idx + 1) % total_options
        elif key == b'\r':  # Enter key
            choice = update_options[selected_idx][0]
            break
        elif key == b'\x1b':  # ESC key
            choice = '0'
            break
        elif key in (b'k', b'K'):  # Vim-style up
            selected_idx = (selected_idx - 1) % total_options
        elif key in (b'j', b'J'):  # Vim-style down
            selected_idx = (selected_idx + 1) % total_options
    
    # Clear screen after selection
    print('\033[2J\033[H', end='')
    
    if choice == '0':
        print_warning('Update cancelled.')
        return vault
    
    existing = vault.get(chosen)
    if isinstance(existing, dict):
        new_name = chosen
        new_pw = existing.get('password')
        new_acct = existing.get('account')
        new_username = existing.get('username')
        new_phone = existing.get('phone_number')
        new_desc = existing.get('description')
    else:
        new_name = chosen
        new_pw = existing
        new_acct = None
        new_username = None
        new_phone = None
        new_desc = None
    if choice == '1':
        new_name = input_box('New website name: ').strip()
        if not new_name:
            print_error('Invalid name.')
            return vault
    if choice == '3':
        new_acct = input_box('New account (optional): ').strip()
        if new_acct and '@' not in new_acct:
            print_warning('The email does not look valid. Saving as entered.')
    if choice == '4':
        new_username = input_box('New username (optional): ').strip()
    if choice == '5':
        new_phone = input_box('New phone (optional): ').strip()
    if choice == '6':
        new_desc = input_box('New description (max 30 words): ').strip()
        if new_desc:
            words = new_desc.split()
            if len(words) > 30:
                new_desc = ' '.join(words[:30])
                print_warning('Description truncated to 30 words.')
    if choice == '2':
        print(f'\n{CYAN}Password Options:{RESET}')
        print(f'  {CYAN}1){RESET} Input your own password')
        print(f'  {CYAN}2){RESET} Generate a strong password')
        c2 = input_box('Choose (1 or 2): ').strip()
        if c2 == '1':
            new_pw = masked_input_box('Enter new password: ')
        else:
            while True:
                length_s = input_box('Password length (8-16, default 16): ').strip()
                if not length_s:
                    length = 16
                    break
                try:
                    length = int(length_s)
                except Exception:
                    print_error('Please enter a number between 8 and 16.')
                    continue
                if length < 8 or length > 16:
                    print_error('Length must be between 8 and 16. Try again.')
                    continue
                break
            new_pw = generate_strong_password(length)
            print_success(f'Generated password: {GREEN}{new_pw}{RESET}')
    mpw = masked_input_box('Master password: ')
    if not verify_master(mpw):
        print_error('Master password incorrect. Update cancelled.')
        write_log('UPDATE_FAILED', chosen)
        return vault
    if new_name != chosen:
        vault.pop(chosen, None)
    existing_created = None
    existing = vault.get(chosen) if new_name == chosen else None
    if isinstance(existing, dict):
        existing_created = existing.get('created')
    if existing_created is None:
        prev = vault.get(new_name)
        if isinstance(prev, dict):
            existing_created = prev.get('created')
    created_val = existing_created if existing_created is not None else datetime.datetime.now().timestamp()
    vault[new_name] = {
        'password': new_pw,
        'account': new_acct,
        'username': new_username,
        'phone_number': new_phone,
        'description': new_desc,
        'created': created_val
    }
    save_vault(vault, mpw)
    print_success('Entry updated successfully!')
    write_log('UPDATE', new_name)
    return vault


def delete_entry(vault):
    if not vault:
        print_warning('No entries found.')
        return vault
    list_short = list_websites(vault)
    list_short(5)
    name = input_box('Website to delete: ').strip()
    matches = search_entries(vault, name)
    if not matches:
        print_warning('No matches found.')
        return vault
    if len(matches) == 1:
        chosen = matches[0]
    else:
        print(f'\n{YELLOW}Matching entries:{RESET}')
        for idx, m in enumerate(matches, 1):
            print(f"  {CYAN}{idx}.{RESET} {m}")
        sel = input_box('Choose number or 0 to cancel: ').strip()
        try:
            si = int(sel)
            if si == 0:
                return vault
            chosen = matches[si-1]
        except Exception:
            print_error('Invalid selection.')
            return vault
    
    # Display entry details before deletion
    entry = vault[chosen]
    print(f'\n{RED}╔═══════════════════════════════╗{RESET}')
    print(f'{RED}║{RESET}  {BOLD}Entry to be deleted{RESET}          {RED}║{RESET}')
    print(f'{RED}╚═══════════════════════════════╝{RESET}\n')
    print_info('Website', chosen, RED + BOLD)
    if isinstance(entry, dict):
        if entry.get('account'):
            print_info('Account', entry.get("account"), YELLOW)
        if entry.get('username'):
            print_info('Username', entry.get("username"), MAGENTA)
        if entry.get('phone_number'):
            print_info('Phone Number', entry.get("phone_number"), BLUE)
        if entry.get('description'):
            print_info('Description', entry.get("description"), GRAY)
    print()
    
    confirm = input_box(f'Delete "{chosen}"? (y/N):').strip().lower()
    if confirm != 'y':
        print_warning('Deletion cancelled.')
        return vault
    mpw = masked_input_box('Master password: ')
    if not verify_master(mpw):
        print_error('Master password incorrect. Deletion cancelled.')
        write_log('DELETE_FAILED', chosen)
        return vault
    vault.pop(chosen, None)
    save_vault(vault, mpw)
    print_success(f'Entry "{chosen}" deleted successfully!')
    write_log('DELETE', chosen)
    return vault


def view_log():
    if not os.path.exists(LOG_FILE):
        print_warning('No log file found yet.')
        return
    
    # Use CYAN color like the website list
    print_header('Action Log History', CYAN)
    
    # Calculate column widths
    try:
        terminal_width = os.get_terminal_size().columns
    except:
        terminal_width = 120
    
    TS_W = 19
    ACT_W = 20
    website_start = TS_W + ACT_W + 8
    max_website_width = terminal_width - website_start - 5
    
    if max_website_width < 20:
        max_website_width = 20
    
    # Print column headers with separator
    print(f'  {BOLD}{CYAN}{"TIMESTAMP":<{TS_W}}{RESET} {GRAY}│{RESET} {BOLD}{CYAN}{"ACTION":<{ACT_W}}{RESET} {GRAY}│{RESET} {BOLD}{CYAN}WEBSITE{RESET}')
    print(f'  {GRAY}{"─" * TS_W} ┼ {"─" * ACT_W} ┼ {"─" * max_website_width}{RESET}')
    
    with open(LOG_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            s = line.strip()
            parts = [p.strip() for p in s.split('|')]
            if len(parts) >= 3:
                ts = parts[0]
                action = parts[1]
                website = ' | '.join(parts[2:])
                
                # Truncate website if too long
                if len(website) > max_website_width:
                    website = website[:max_website_width - 3] + '...'
                
                # Color code actions
                if 'FAILED' in action:
                    action_color = RED
                elif 'SUCCESS' in action or 'CREATE' in action or 'UPDATE' in action:
                    action_color = GREEN
                elif 'DELETE' in action:
                    action_color = YELLOW
                else:
                    action_color = CYAN
                
                print(f"  {GRAY}{ts:<{TS_W}}{RESET} {GRAY}│{RESET} {action_color}{action:<{ACT_W}}{RESET} {GRAY}│{RESET} {website}")
            else:
                print(f'  {s}')
    print()


def clear_log():
    if not os.path.exists(LOG_FILE):
        print_warning('No log file found to clear.')
        return
    
    # Read all log entries
    with open(LOG_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    total_entries = len(lines)
    if total_entries == 0:
        print_warning('Log is already empty.')
        return
    
    print(f'\n{CYAN}Total log entries: {BOLD}{total_entries}{RESET}\n')
    print(f'{CYAN}Clear Options:{RESET}')
    print(f'  • Enter a {BOLD}number{RESET} (1-{total_entries}) to clear that many oldest entries')
    print(f'  • Enter {RED}{BOLD}0{RESET} to clear {BOLD}ALL{RESET} entries')
    print(f'  • Press {GRAY}Ctrl+C{RESET} to cancel\n')
    
    try:
        choice = input_box('Number of oldest entries to clear (0 for all):').strip()
        
        if not choice:
            print_warning('Clear operation cancelled.')
            return
        
        try:
            entries_to_clear = int(choice)
        except ValueError:
            print_error('Please enter a valid number.')
            return
        
        if entries_to_clear < 0:
            print_error('Number must be 0 or positive.')
            return
        
        if entries_to_clear == 0:
            entries_to_clear = total_entries
            confirm_msg = f'Are you sure you want to clear ALL {total_entries} entries? (y/N):'
        elif entries_to_clear > total_entries:
            entries_to_clear = total_entries
            confirm_msg = f'Only {total_entries} entries available. Clear all? (y/N):'
        else:
            confirm_msg = f'Clear the oldest {entries_to_clear} entries? (y/N):'
        
        confirm = input_box(confirm_msg).strip().lower()
        if confirm != 'y':
            print_warning('Clear operation cancelled.')
            return
        
        # Verify master password
        mpw = masked_input_box('Master password:')
        if not verify_master(mpw):
            print_error('Master password incorrect. Clear cancelled.')
            write_log('CLEAR_LOG_FAILED')
            return
        
        # Clear entries (oldest first)
        if entries_to_clear == total_entries:
            # Clear all - truncate the file
            with open(LOG_FILE, 'w', encoding='utf-8') as f:
                pass
            print_success(f'All {total_entries} entries cleared!')
        else:
            # Keep the last (total - entries_to_clear) entries, remove oldest first
            remaining_lines = lines[entries_to_clear:]
            with open(LOG_FILE, 'w', encoding='utf-8') as f:
                f.writelines(remaining_lines)
            print_success(f'Cleared oldest {entries_to_clear} entries. {len(remaining_lines)} remaining.')
        
        write_log('CLEAR_LOG', f'Cleared {entries_to_clear} entries')
    
    except KeyboardInterrupt:
        print_warning('\nClear operation cancelled.')
        return


def show_about():
    """Display information about the program."""
    print_header('About Vanessa Kang', CYAN)
    
    print(f'{BOLD}{CYAN}Project Name:{RESET} Vanessa Kang')
    print(f'{BOLD}{CYAN}Created by:{RESET} Ream Daly')
    print(f'{BOLD}{CYAN}Date Created:{RESET} October 23, 2025')
    print(f'{BOLD}{CYAN}Version:{RESET} 1.0.0')
    print(f'{BOLD}{CYAN}Type:{RESET} Terminal Password Manager\n')
    
    print(f'{BOLD}{GREEN}✓ Features:{RESET}')
    print(f'  {GRAY}▸{RESET} Master password with strength validation')
    print(f'  {GRAY}▸{RESET} Military-grade encryption (PBKDF2-HMAC-SHA256 + Fernet)')
    print(f'  {GRAY}▸{RESET} Secure credential storage (website, account, username, phone)')
    print(f'  {GRAY}▸{RESET} CRUD operations: Create, Read, Update, Delete')
    print(f'  {GRAY}▸{RESET} Password generator (8-16 characters, fully customizable)')
    print(f'  {GRAY}▸{RESET} Action logging and history tracking')
    print(f'  {GRAY}▸{RESET} Automatic backups with restore functionality')
    print(f'  {GRAY}▸{RESET} Session timeout (90 minutes inactivity)')
    print(f'  {GRAY}▸{RESET} Clipboard integration (optional)')
    print(f'  {GRAY}▸{RESET} Beautiful terminal UI with arrow-key navigation\n')
    
    print(f'{BOLD}{BLUE}⚙ Technical Details:{RESET}')
    print(f'  {GRAY}▸{RESET} Language: Python 3')
    print(f'  {GRAY}▸{RESET} Encryption: Fernet (symmetric encryption)')
    print(f'  {GRAY}▸{RESET} Key Derivation: PBKDF2-HMAC-SHA256 (390,000 iterations)')
    print(f'  {GRAY}▸{RESET} Storage: Encrypted binary vault + salted hash')
    print(f'  {GRAY}▸{RESET} Backups: Timestamped, organized by type (vault/master/logs)\n')
    
    print(f'{BOLD}{MAGENTA}📂 Files:{RESET}')
    print(f'  {GRAY}▸{RESET} {BOLD}master.hash{RESET} - Master password hash')
    print(f'  {GRAY}▸{RESET} {BOLD}vault.bin{RESET} - Encrypted credentials vault')
    print(f'  {GRAY}▸{RESET} {BOLD}actions.log{RESET} - Activity log (plaintext)\n')
    
    print(f'{BOLD}{YELLOW}⚠ Security Notice:{RESET}')
    print(f'  This is a local password manager. Keep your files secure and backup')
    print(f'  your master password safely. Lost master passwords cannot be recovered.\n')
    
    print(f'{GRAY}Press Enter to return to main menu...{RESET}')
    input()


def restore_from_backup():
    """Restore vault, master.hash, and actions.log from timestamped backups in subfolders."""
    if not os.path.exists(BACKUP_DIR):
        print_error('No backup directory found.')
        return
    
    print_header('Restore From Backup', CYAN)
    print(f'{YELLOW}⚠ Warning: This will replace your current files!{RESET}\n')
    
    # Get all vault backups with timestamps from vaults subfolder
    vaults_dir = os.path.join(BACKUP_DIR, BACKUP_SUBDIRS['vault'])
    if not os.path.exists(vaults_dir):
        print_error('No vault backups found.')
        return
    
    vault_backups = []
    for file in os.listdir(vaults_dir):
        if file.startswith('vault_') and file.endswith('.bin'):
            file_path = os.path.join(vaults_dir, file)
            mtime = os.path.getmtime(file_path)
            vault_backups.append((file, mtime, file_path))
    
    if not vault_backups:
        print_error('No timestamped backups found.')
        return
    
    # Sort by modification time (newest first)
    vault_backups.sort(key=lambda x: x[1], reverse=True)
    
    # Read log file to get actions with website names for each backup timestamp
    log_entries = {}
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                parts = [p.strip() for p in line.strip().split('|')]
                if len(parts) >= 2:
                    timestamp = parts[0]
                    action = parts[1]
                    website = parts[2] if len(parts) >= 3 else ''
                    
                    # Create descriptive action text
                    if website:
                        action_text = f"{action} - {website}"
                    else:
                        action_text = action
                    
                    # Store action with timestamp key (just date and time, no seconds)
                    key = timestamp[:16]  # Get YYYY-MM-DD HH:MM
                    log_entries[key] = action_text
    
    # Limit to 15 most recent backups
    display_backups = vault_backups[:15]
    
    # Prepare backup list with descriptions
    backup_options = []
    for idx, (filename, mtime, file_path) in enumerate(display_backups, 1):
        timestamp = datetime.datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
        timestamp_key = timestamp[:16]
        action = log_entries.get(timestamp_key, 'BACKUP')
        backup_options.append((idx, timestamp, action, filename, mtime, file_path))
    
    # Interactive arrow-key selection
    selected_idx = 0
    total_options = len(backup_options)
    
    # Calculate column widths
    try:
        terminal_width = os.get_terminal_size().columns
    except:
        terminal_width = 120
    
    timestamp_width = 20
    max_action_width = terminal_width - timestamp_width - 15
    if max_action_width < 30:
        max_action_width = 30
    
    while True:
        # Clear screen and show header
        print('\033[2J\033[H', end='')
        print_header('Restore From Backup', CYAN)
        print(f'{YELLOW}⚠ Warning: This will replace your current files!{RESET}\n')
        
        # Print column headers
        print(f'  {BOLD}{CYAN}{"#":<3}{RESET}  {BOLD}{CYAN}{"TIMESTAMP":<{timestamp_width}}{RESET} {GRAY}│{RESET} {BOLD}{CYAN}ACTION{RESET}')
        print(f'  {GRAY}{"─" * 3}  {"─" * timestamp_width} ┼ {"─" * max_action_width}{RESET}')
        
        # Display options
        for idx, (num, timestamp, action, _, _, _) in enumerate(backup_options):
            # Truncate action if too long
            display_action = action
            if len(display_action) > max_action_width:
                display_action = display_action[:max_action_width - 3] + '...'
            
            # Color code the action
            if 'FAILED' in action:
                action_color = RED
            elif 'CREATE' in action or 'UPDATE' in action or 'SET_MASTER' in action:
                action_color = GREEN
            elif 'DELETE' in action or 'CLEAR' in action:
                action_color = YELLOW
            else:
                action_color = CYAN
            
            if idx == selected_idx:
                # Highlighted option
                print(f'  {REVERSE}{CYAN}{num:>2}.  {timestamp:<{timestamp_width}} │ {display_action}{RESET}')
            else:
                # Normal option
                print(f'  {DIM}{CYAN}{num:>2}.{RESET}  {DIM}{timestamp:<{timestamp_width}}{RESET} {GRAY}│{RESET} {action_color}{display_action}{RESET}')
        
        print(f'\n{DIM}  (Use ↑↓ arrows and Enter to select, or press 0 to cancel){RESET}')
        
        # Read arrow keys
        key = msvcrt.getch()
        
        if key == b'\xe0' or key == b'\x00':  # Arrow key prefix
            key = msvcrt.getch()
            if key == b'H':  # Up arrow
                selected_idx = (selected_idx - 1) % total_options
            elif key == b'P':  # Down arrow
                selected_idx = (selected_idx + 1) % total_options
        elif key == b'\r':  # Enter key
            choice_num = backup_options[selected_idx][0]
            break
        elif key == b'\x1b':  # ESC key
            choice_num = 0
            break
        elif key in (b'k', b'K'):  # Vim-style up
            selected_idx = (selected_idx - 1) % total_options
        elif key in (b'j', b'J'):  # Vim-style down
            selected_idx = (selected_idx + 1) % total_options
        elif key == b'0':  # Press 0 to cancel
            choice_num = 0
            break
    
    # Clear screen after selection
    print('\033[2J\033[H', end='')
    
    if choice_num == 0:
        print_warning('Restore cancelled.')
        return
    
    # Get selected backup info
    selected_backup = backup_options[selected_idx]
    selected_filename = selected_backup[3]
    selected_vault_path = selected_backup[5]
    
    timestamp_str = selected_filename[6:-4]
    
    # Construct paths for corresponding master.hash and actions.log backups
    master_dir = os.path.join(BACKUP_DIR, BACKUP_SUBDIRS['master'])
    actions_dir = os.path.join(BACKUP_DIR, BACKUP_SUBDIRS['actions'])
    
    selected_master_filename = f'master_{timestamp_str}.hash'
    selected_actions_filename = f'actions_{timestamp_str}.log'
    
    selected_master_path = os.path.join(master_dir, selected_master_filename)
    selected_actions_path = os.path.join(actions_dir, selected_actions_filename)
    
    # Check if all three files exist
    files_exist = {
        'vault': os.path.exists(selected_vault_path),
        'master': os.path.exists(selected_master_path),
        'log': os.path.exists(selected_actions_path)
    }
    
    print_header('Backup File Status', CYAN)
    print(f'  {GREEN}✓{RESET} Vault' if files_exist["vault"] else f'  {RED}✗{RESET} Vault')
    print(f'  {GREEN}✓{RESET} Master' if files_exist["master"] else f'  {RED}✗{RESET} Master')
    print(f'  {GREEN}✓{RESET} Log\n' if files_exist["log"] else f'  {RED}✗{RESET} Log\n')
    
    if not files_exist['vault'] or not files_exist['master']:
        print_error('Critical files missing from backup. Cannot restore.')
        return
    
    # Verify master password before restore
    mpw = masked_input_box('Master password:')
    if not verify_master(mpw):
        print_error('Master password incorrect. Restore cancelled.')
        write_log('RESTORE_FAILED')
        return
    
    confirm = input_box('Are you SURE you want to restore? Current data will be lost! (y/N):').strip().lower()
    if confirm != 'y':
        print_warning('Restore cancelled.')
        return
    
    # Perform restore
    try:
        shutil.copy2(selected_vault_path, VAULT_FILE)
        shutil.copy2(selected_master_path, MASTER_HASH_FILE)
        if files_exist['log']:
            shutil.copy2(selected_actions_path, LOG_FILE)
        
        print_success('Restore completed successfully!')
        print(f'{YELLOW}  Please restart the program to use the restored data.{RESET}')
        write_log('RESTORE_SUCCESS', selected_filename)
        sys.exit(0)
        
    except Exception as e:
        print_error(f'Restore failed: {e}')
        write_log('RESTORE_ERROR')



def main():
    global last_activity_time
    
    if not os.path.exists(MASTER_HASH_FILE):
        set_master_password()

    update_activity_time()  # Initialize activity time
    for _ in range(3):
        mpw = masked_input_box('Master password:')
        if verify_master(mpw):
            try:
                vault = load_vault(mpw)
            except Exception as e:
                print('Failed to load vault:', e)
                vault = {}
            break
        else:
            print('Incorrect master password.')
    else:
        print('Too many failed attempts. Exiting.')
        sys.exit(1)

    while True:
        # Display interactive menu with arrow key navigation
        choice = interactive_menu()
        
        if choice == '1':
            vault = create_entry(vault)
            save_vault(vault, mpw)
        elif choice == '2':
            read_entry(vault)
        elif choice == '3':
            vault = update_entry(vault)
        elif choice == '4':
            vault = delete_entry(vault)
        elif choice == '5':
            list_all = list_websites(vault)
            list_all(None)
        elif choice == '6':
            view_log()
        elif choice == '7':
            clear_log()
        elif choice == '8':
            restore_from_backup()
        elif choice == '9':
            cur = masked_input_box('Current master password:')
            if not verify_master(cur):
                print_error('Incorrect master password.')
                write_log('CHANGE_MASTER_FAILED')
            else:
                while True:
                    new1 = masked_input_box('New master password:')
                    new2 = masked_input_box('Repeat new master password:')
                    if new1 != new2:
                        print_error('Passwords do not match.')
                        continue
                    if not is_strong_password(new1):
                        print_error('Password not strong enough.')
                        cont = input_box('Try again? (y to retry):').strip().lower()
                        if cont == 'y':
                            continue
                        else:
                            break
                    salt = secrets.token_bytes(16)
                    key = derive_key(new1.encode('utf-8'), salt)
                    f = Fernet(key)
                    token = f.encrypt(b'verify')
                    with open(MASTER_HASH_FILE, 'wb') as fh:
                        fh.write(salt + b'--' + token)
                    save_vault(vault, new1)
                    backup_files()  # Backup after changing master password
                    mpw = new1
                    print_success('Master password changed successfully!')
                    write_log('CHANGE_MASTER')
                    break
        elif choice == 'c' or choice == 'C':
            # Clear terminal screen
            os.system('cls' if os.name == 'nt' else 'clear')
        elif choice == 'a' or choice == 'A':
            show_about()
        elif choice == '0':
            print(f'\n{CYAN}Goodbye! Stay secure! 👋{RESET}')
            break
        else:
            print_error('Unknown option.')

if __name__ == '__main__':
    main()
