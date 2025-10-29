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

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except Exception as e:
    print("\t\tThis program requires the 'cryptography' package. Install it with: pip install cryptography")
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

# Global variable to track last activity time
last_activity_time = time.time()


def update_activity_time():
    """Update the last activity timestamp."""
    global last_activity_time
    last_activity_time = time.time()


def check_timeout():
    """Check if the program has been inactive for too long."""
    global last_activity_time
    elapsed = time.time() - last_activity_time
    if elapsed >= TIMEOUT_SECONDS:
        print('\n\t\tSession timed out due to inactivity (90 minutes). Exiting for security.')
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
        print('\n\t\tExiting...')
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

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def set_master_password():
    print('\n\t\tNo master password found. Let\'s create one.')
    while True:
        pw1 = masked_input('\n\t\tEnter new master password: ')
        pw2 = masked_input('\t\tRepeat master password: ')
        if pw1 != pw2:
            print('\n\t\tPasswords do not match. Try again.')
            continue
        if not is_strong_password(pw1):
            print('\n\t\tPassword not strong enough. Requirements: at least 12 chars, upper, lower, digit, symbol.')
            choice = pretty_input('\t\tDo you want automatic strong password suggestion? (y/n): ').strip().lower()
            if choice == 'y':
                suggested = generate_strong_password(16)
                print('\n\t\tSuggested strong password (copy and save it somewhere safe):', suggested)
                use = pretty_input('\n\t\tUse this suggested password? (y to use, anything else to try again): ').strip().lower()
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
        print('\n\t\tMaster password saved.')
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
        raise ValueError('\n\t\tUnable to decrypt vault. Wrong master password or corrupted vault.')


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
    name = pretty_input('\t\tWebsite name: ').strip()
    if not name:
        print('\t\tWebsite name cannot be empty.')
        return vault
    account = pretty_input('\t\tGmail / Microsoft account email (optional): ').strip()
    if account and '@' not in account:
        print('\t\tWarning: the email you entered does not look like a valid email. Saving as entered.')
    
    # New optional fields
    username = pretty_input('\t\tUsername (optional): ').strip()
    phone_number = pretty_input('\t\tPhone number (optional): ').strip()
    
    print('\t\t1) Input your own password (no strength checking)')
    print('\t\t2) Generate a strong password for me')
    choice = pretty_input('\t\tChoose (1 or 2): ').strip()
    if choice == '1':
        pw = masked_input('\t\tEnter password for %s: ' % name)
    else:
        while True:
            length_s = pretty_input('\t\tGenerated password length (8-16, default 16): ').strip()
            if not length_s:
                length = 16
                break
            try:
                length = int(length_s)
            except Exception:
                print('\t\tPlease enter a number between 8 and 16.')
                continue
            if length < 8 or length > 16:
                print('\t\tLength must be between 8 and 16. Try again.')
                continue
            break
        pw = generate_strong_password(length)
        print('\t\tGenerated password: ', pw)
    vault[name] = {
        'password': pw,
        'account': account,
        'username': username,
        'phone_number': phone_number,
        'created': datetime.datetime.now().timestamp()
    }
    print('\t\tSaved.')
    write_log('CREATE', name)
    return vault


def list_websites(vault):
    def _inner(max_items=None):
        if not vault:
            print('\t\tNo entries.')
            return
        def _created_key(k):
            e = vault.get(k)
            if isinstance(e, dict):
                return e.get('created', 0)
            return 0
        keys = sorted(vault.keys(), key=_created_key, reverse=True)
        print('\t\tStored websites:')
        to_show = keys if (max_items is None) else keys[:max_items]
        for i, k in enumerate(to_show, 1):
            print(f"\t\t{i}. {k}")
        if max_items is not None and len(keys) > max_items:
            print('\t\t...')
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
    q = pretty_input('\n\t\tEnter website name to search (or partial): ').strip()
    matches = search_entries(vault, q)
    if not matches:
        print('\n\t\tNo matches found.')
        return
    if len(matches) == 1:
        chosen = matches[0]
    else:
        print('\t\tMatches:')
        for idx, m in enumerate(matches, 1):
            print(f"\t\t{idx}. {m}")
        sel = pretty_input('\t\tChoose number or 0 to cancel: ').strip()
        try:
            si = int(sel)
            if si == 0:
                return
            chosen = matches[si-1]
        except Exception:
            print('\t\tInvalid selection.')
            return
    mpw = masked_input('\t\tEnter master password: ')
    if not verify_master(mpw):
        print('\n\t\tMaster password incorrect.')
        write_log('READ_FAILED', chosen)
        return
    entry = vault[chosen]
    if isinstance(entry, dict):
        pw = entry.get('password')
        acct = entry.get('account')
        username = entry.get('username')
        phone = entry.get('phone_number')
    else:
        pw = entry
        acct = None
        username = None
        phone = None
    print(f'\n\t\tWebsite: {chosen}')
    if acct:
        print(f'\t\tAccount: {acct}')
    if username:
        print(f'\t\tUsername: {username}')
    if phone:
        print(f'\t\tPhone Number: {phone}')
    print(f'\t\tPassword: {pw}')
    write_log('READ', chosen)


def update_entry(vault):
    if not vault:
        print('\t\tNo entries.')
        return vault
    list_short = list_websites(vault)
    list_short(5)
    name = pretty_input('\n\t\tEnter website name to update (or partial): ').strip()
    matches = search_entries(vault, name)
    if not matches:
        print('\t\tNo matches.')
        return vault
    if len(matches) == 1:
        chosen = matches[0]
    else:
        for idx, m in enumerate(matches, 1):
            print(f"\n\t\t{idx}. {m}")
        sel = pretty_input('\t\tChoose number or 0 to cancel: ').strip()
        try:
            si = int(sel)
            if si == 0:
                return vault
            chosen = matches[si-1]
        except Exception:
            print('\t\tInvalid selection.')
            return vault
    print('\t\tWhat do you want to change?')
    print('\t\t1) Change website name')
    print('\t\t2) Change password')
    print('\t\t3) Change account (Gmail/Microsoft email)')
    print('\t\t4) Change username')
    print('\t\t5) Change phone number')
    print('\t\t0) Cancel')
    choice = pretty_input('\t\tChoose (1/2/3/4/5/0): ').strip()
    
    if choice == '0':
        print('\t\tCancelled.')
        return vault
    
    existing = vault.get(chosen)
    if isinstance(existing, dict):
        new_name = chosen
        new_pw = existing.get('password')
        new_acct = existing.get('account')
        new_username = existing.get('username')
        new_phone = existing.get('phone_number')
    else:
        new_name = chosen
        new_pw = existing
        new_acct = None
        new_username = None
        new_phone = None
    if choice == '1':
        new_name = pretty_input('\t\tNew website name: ').strip()
        if not new_name:
            print('\t\tInvalid name.')
            return vault
    if choice == '3':
        new_acct = pretty_input('\t\tNew account email (leave blank to clear): ').strip()
        if new_acct and '@' not in new_acct:
            print('\t\tWarning: the email you entered does not look like a valid email. Saving as entered.')
    if choice == '4':
        new_username = pretty_input('\t\tNew username (leave blank to clear): ').strip()
    if choice == '5':
        new_phone = pretty_input('\t\tNew phone number (leave blank to clear): ').strip()
    if choice == '2':
        print('\t\t1) Input your own password (no strength checking)')
        print('\t\t2) Generate a strong password for me')
        c2 = pretty_input('\t\tChoose (1 or 2): ').strip()
        if c2 == '1':
            new_pw = masked_input('\t\tEnter new password: ')
        else:
            while True:
                length_s = pretty_input('\t\tGenerated password length (8-16, default 16): ').strip()
                if not length_s:
                    length = 16
                    break
                try:
                    length = int(length_s)
                except Exception:
                    print('\t\tPlease enter a number between 8 and 16.')
                    continue
                if length < 8 or length > 16:
                    print('\t\tLength must be between 8 and 16. Try again.')
                    continue
                break
            new_pw = generate_strong_password(length)
            print('\t\tGenerated password: ', new_pw)
    mpw = masked_input('\t\tEnter master password to confirm update: ')
    if not verify_master(mpw):
        print('\t\tMaster password incorrect. Update cancelled.')
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
        'created': created_val
    }
    save_vault(vault, mpw)
    print('\t\tUpdated.')
    write_log('UPDATE', new_name)
    return vault


def delete_entry(vault):
    if not vault:
        print('\t\tNo entries.')
        return vault
    list_short = list_websites(vault)
    list_short(5)
    name = pretty_input('\t\tEnter website name to delete (or partial): ').strip()
    matches = search_entries(vault, name)
    if not matches:
        print('\t\tNo matches.')
        return vault
    if len(matches) == 1:
        chosen = matches[0]
    else:
        for idx, m in enumerate(matches, 1):
            print(f"\t\t{idx}. {m}")
        sel = pretty_input('\t\tChoose number or 0 to cancel: ').strip()
        try:
            si = int(sel)
            if si == 0:
                return vault
            chosen = matches[si-1]
        except Exception:
            print('\t\tInvalid selection.')
            return vault
    
    # Display entry details before deletion
    entry = vault[chosen]
    print(f'\n\t\tEntry to delete:')
    print(f'\t\tWebsite: {chosen}')
    if isinstance(entry, dict):
        if entry.get('account'):
            print(f'\t\tAccount: {entry.get("account")}')
        if entry.get('username'):
            print(f'\t\tUsername: {entry.get("username")}')
        if entry.get('phone_number'):
            print(f'\t\tPhone Number: {entry.get("phone_number")}')
    
    confirm = pretty_input(f'\n\t\tAre you sure you want to delete "{chosen}"? (y/N): ').strip().lower()
    if confirm != 'y':
        print('\t\tCancelled.')
        return vault
    mpw = masked_input('\t\tEnter master password to confirm deletion: ')
    if not verify_master(mpw):
        print('\t\tMaster password incorrect. Deletion cancelled.')
        write_log('DELETE_FAILED', chosen)
        return vault
    vault.pop(chosen, None)
    save_vault(vault, mpw)
    print('\n\t\tDeleted.')
    write_log('DELETE', chosen)
    return vault


def view_log():
    if not os.path.exists(LOG_FILE):
        print('\t\tNo log yet.')
        return
    print('\n\t\tACTION LOG:')
    TS_W = 19
    ACT_W = 15
    with open(LOG_FILE, 'r', encoding='utf-8') as f:
        header = f"\t\t{'TIMESTAMP':{TS_W}} | {'ACTION':{ACT_W}} | WEBSITE"
        print(header)
        print('\t\t' + '-' * (TS_W + 3 + ACT_W + 3 + 20))
        for line in f:
            s = line.strip()
            parts = [p.strip() for p in s.split('|')]
            if len(parts) >= 3:
                ts = parts[0]
                action = parts[1]
                website = ' | '.join(parts[2:])
                print(f"\t\t{ts:{TS_W}} | {action:{ACT_W}} | {website}")
            else:
                print('\t\t' + s)
    print('\t\t')


def clear_log():
    if not os.path.exists(LOG_FILE):
        print('\t\tNo log to clear.')
        return
    
    # Read all log entries
    with open(LOG_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    total_entries = len(lines)
    if total_entries == 0:
        print('\t\tLog is already empty.')
        return
    
    print(f'\n\t\tTotal log entries: {total_entries}')
    print('\t\tClear options:')
    print('\t\t1) Clear last 10 entries')
    print('\t\t2) Clear last 20 entries')
    print('\t\t3) Clear all entries')
    print('\t\t0) Cancel')
    
    choice = pretty_input('\n\t\tChoose (1/2/3/0): ').strip()
    
    if choice == '0':
        print('\t\tCancelled.')
        return
    
    entries_to_clear = 0
    if choice == '1':
        entries_to_clear = min(10, total_entries)
    elif choice == '2':
        entries_to_clear = min(20, total_entries)
    elif choice == '3':
        entries_to_clear = total_entries
    else:
        print('\t\tInvalid option.')
        return
    
    if entries_to_clear == total_entries:
        confirm_msg = f'\t\tAre you sure you want to clear ALL {total_entries} entries? (y/N): '
    else:
        confirm_msg = f'\t\tAre you sure you want to clear the oldest {entries_to_clear} entries? (y/N): '
    
    confirm = pretty_input(confirm_msg).strip().lower()
    if confirm != 'y':
        print('\t\tCancelled.')
        return
    
    # Verify master password
    mpw = masked_input('\t\tEnter master password to confirm: ')
    if not verify_master(mpw):
        print('\n\t\tMaster password incorrect. Clear cancelled.')
        write_log('CLEAR_LOG_FAILED')
        return
    
    # Clear entries (oldest first)
    if entries_to_clear == total_entries:
        # Clear all - truncate the file
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            pass
        print(f'\n\t\tAll {total_entries} entries cleared.')
    else:
        # Keep the last (total - entries_to_clear) entries, remove oldest first
        remaining_lines = lines[entries_to_clear:]
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.writelines(remaining_lines)
        print(f'\n\t\tCleared oldest {entries_to_clear} entries. {len(remaining_lines)} entries remaining.')
    
    write_log('CLEAR_LOG', f'Cleared {entries_to_clear} entries')


def restore_from_backup():
    """Restore vault, master.hash, and actions.log from timestamped backups in subfolders."""
    if not os.path.exists(BACKUP_DIR):
        print('\t\tNo backup directory found.')
        return
    
    print('\n\t\t===== RESTORE FROM BACKUP =====')
    print('\t\tWarning: This will replace your current files!')
    print('\t\t================================')
    
    # Get all vault backups with timestamps from vaults subfolder
    vaults_dir = os.path.join(BACKUP_DIR, BACKUP_SUBDIRS['vault'])
    if not os.path.exists(vaults_dir):
        print('\t\tNo vault backups found.')
        return
    
    vault_backups = []
    for file in os.listdir(vaults_dir):
        if file.startswith('vault_') and file.endswith('.bin'):
            file_path = os.path.join(vaults_dir, file)
            mtime = os.path.getmtime(file_path)
            vault_backups.append((file, mtime, file_path))
    
    if not vault_backups:
        print('\t\tNo timestamped backups found.')
        return
    
    # Sort by modification time (newest first)
    vault_backups.sort(key=lambda x: x[1], reverse=True)
    
    print('\n\t\tAvailable backups:')
    for idx, (filename, mtime, _) in enumerate(vault_backups[:15], 1):  # Show last 15
        timestamp = datetime.datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
        # Extract timestamp from filename for display
        parts = filename.replace('vault_', '').replace('.bin', '').split('_')
        if len(parts) >= 2:
            display_time = f"{parts[0]} {parts[1].replace('-', ':')}"
        else:
            display_time = timestamp
        print(f'\t\t{idx}. {display_time}')
    
    choice = pretty_input('\n\t\tChoose backup number (or 0 to cancel): ').strip()
    
    try:
        choice_num = int(choice)
        if choice_num == 0:
            print('\t\tCancelled.')
            return
        if choice_num < 1 or choice_num > len(vault_backups):
            print('\t\tInvalid selection.')
            return
        
        selected_vault = vault_backups[choice_num - 1]
        selected_filename = selected_vault[0]
        
        # Extract timestamp from vault filename
        timestamp_str = selected_filename.replace('vault_', '').replace('.bin', '')
        
        # Build corresponding master.hash and actions.log paths in their subfolders
        master_dir = os.path.join(BACKUP_DIR, BACKUP_SUBDIRS['master'])
        actions_dir = os.path.join(BACKUP_DIR, BACKUP_SUBDIRS['actions'])
        
        master_backup = os.path.join(master_dir, f'master_{timestamp_str}.hash')
        log_backup = os.path.join(actions_dir, f'actions_{timestamp_str}.log')
        vault_backup = selected_vault[2]
        
        # Check if all three files exist
        files_exist = {
            'vault': os.path.exists(vault_backup),
            'master': os.path.exists(master_backup),
            'log': os.path.exists(log_backup)
        }
        
        print(f'\n\t\tFiles found in this backup:')
        print(f'\t\t  Vault: {"✓" if files_exist["vault"] else "✗"}')
        print(f'\t\t  Master: {"✓" if files_exist["master"] else "✗"}')
        print(f'\t\t  Log: {"✓" if files_exist["log"] else "✗"}')
        
        if not files_exist['vault'] or not files_exist['master']:
            print('\n\t\tCritical files missing from backup. Cannot restore.')
            return
        
        # Verify master password before restore
        mpw = masked_input('\n\t\tEnter current master password to authorize restore: ')
        if not verify_master(mpw):
            print('\n\t\tMaster password incorrect. Restore cancelled.')
            write_log('RESTORE_FAILED')
            return
        
        confirm = pretty_input('\n\t\tAre you SURE you want to restore? Current data will be lost! (y/N): ').strip().lower()
        if confirm != 'y':
            print('\t\tCancelled.')
            return
        
        # Perform restore
        try:
            shutil.copy2(vault_backup, VAULT_FILE)
            shutil.copy2(master_backup, MASTER_HASH_FILE)
            if files_exist['log']:
                shutil.copy2(log_backup, LOG_FILE)
            
            print('\n\t\t✓ Restore completed successfully!')
            print('\t\t  Please restart the program to use the restored data.')
            write_log('RESTORE_SUCCESS', selected_filename)
            sys.exit(0)
            
        except Exception as e:
            print(f'\n\t\tRestore failed: {e}')
            write_log('RESTORE_ERROR')
            
    except ValueError:
        print('\t\tInvalid input.')
        return


def main():
    global last_activity_time
    
    if not os.path.exists(MASTER_HASH_FILE):
        set_master_password()

    update_activity_time()  # Initialize activity time
    for _ in range(3):
        mpw = masked_input('\n\t\tEnter master password to unlock vault: ')
        if verify_master(mpw):
            try:
                vault = load_vault(mpw)
            except Exception as e:
                print('\t\tFailed to load vault:', e)
                vault = {}
            break
        else:
            print('\n\t\tIncorrect master password.')
    else:
        print('\t\tToo many failed attempts. Exiting.')
        sys.exit(1)

    while True:
        print('\n\t\t=======================')
        print('\n\t\t---- Vannnesa Kang ----')
        print('\t\t-----------------------')
        print('\t\t    Password Manager')
        print('\t\t=======================')
        print('\n\t\t1) Create entry')
        print('\t\t2) Read / View entry')
        print('\t\t3) Update entry')
        print('\t\t4) Delete entry')
        print('\t\t5) List all websites')
        print('\t\t6) View action log')
        print('\t\t7) Clear action log')
        print('\t\t8) Restore from backup')
        print('\t\t9) Change master password')
        print('\t\t0) Exit')
        choice = pretty_input('\n\t\tChoose: ').strip()
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
            cur = masked_input('\n\t\tEnter current master password: ')
            if not verify_master(cur):
                print('\t\tIncorrect.')
                write_log('\t\tCHANGE_MASTER_FAILED')
            else:
                while True:
                    new1 = masked_input('\n\t\tEnter new master password: ')
                    new2 = masked_input('\t\tRepeat new master password: ')
                    if new1 != new2:
                        print('\t\tNot the same.')
                        continue
                    if not is_strong_password(new1):
                        print('\t\tNot strong enough.')
                        cont = pretty_input('\t\tTry again? (y to retry): ').strip().lower()
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
                    print('\t\tMaster password changed.')
                    write_log('\t\tCHANGE_MASTER')
                    break
        elif choice == '0':
            print('\n\t\tGoodbye.')
            break
        else:
            print('\n\t\tUnknown option.')

if __name__ == '__main__':
    main()
