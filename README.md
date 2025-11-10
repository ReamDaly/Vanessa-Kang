# Vanessa-Kang
Password Manager
# Vanessa Kang - Secure Password Manager

```
  ██╗   ██╗ █████╗ ███╗   ██╗███████╗███████╗███████╗ █████╗     ██╗  ██╗ █████╗ ███╗   ██╗ ██████╗
  ██║   ██║██╔══██╗████╗  ██║██╔════╝██╔════╝██╔════╝██╔══██╗    ██║ ██╔╝██╔══██╗████╗  ██║██╔════╝
  ██║   ██║███████║██╔██╗ ██║█████╗  ███████╗███████╗███████║    █████╔╝ ███████║██╔██╗ ██║██║  ███╗
  ╚██╗ ██╔╝██╔══██║██║╚██╗██║██╔══╝  ╚════██║╚════██║██╔══██║    ██╔═██╗ ██╔══██║██║╚██╗██║██║   ██║
   ╚████╔╝ ██║  ██║██║ ╚████║███████╗███████║███████║██║  ██║    ██║  ██╗██║  ██║██║ ╚████║╚██████╔╝
    ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝
```

## 📋 Project Information

**Project Name:** Vanessa Kang  
**Developer:** Ream Daly  
**Project Type:** Terminal-Based Password Manager  
**Date Created:** October 23, 2025  
**Last Updated:** October 31, 2025  
**Version:** 2.0  
**Language:** Python 3.x

---

## 🎯 About This Project

**Vanessa Kang** is a secure, terminal-based password manager with a modern, colorful interface inspired by Gemini CLI. It provides military-grade encryption to safely store and manage your passwords, credentials, and sensitive information all from the comfort of your terminal.

### Key Features:

- 🔐 **Military-Grade Encryption** - AES-256 encryption via Fernet (cryptography library)
- 🎨 **Beautiful CLI Interface** - Modern, colorful design with interactive arrow-key navigation
- 📝 **Complete CRUD Operations** - Create, Read, Update, Delete entries with ease
- 🔄 **Automatic Backups** - Timestamped backups with restore functionality
- 📊 **Action Logging** - Track all activities with detailed logs
- 🔒 **Session Timeout** - Auto-logout after 90 minutes of inactivity
- 📋 **Clipboard Integration** - One-click password copying
- 🎲 **Password Generator** - Create strong, random passwords
- 🛡️ **Brute Force Protection** - Max 3 failed login attempts

---

## 📂 File Structure

Your Vanessa Kang directory contains the following files:

### Core Files:

1. **`VanessaKang.py`** (Main Program)

   - The main executable file containing all program logic
   - Run this file to start the password manager
   - Size: ~1,400+ lines of Python code

2. **`master.hash`** (Master Password File)

   - Stores your master password as a salted PBKDF2-HMAC-SHA256 hash
   - **CRITICAL:** Never delete or share this file
   - Created automatically on first run
   - Contains: `[salt]--[encrypted_token]`

3. **`vault.bin`** (Encrypted Vault)

   - Stores all your passwords and credentials in encrypted format
   - Encrypted using Fernet with AES-256
   - Each save creates a new encryption key from your master password
   - Cannot be read without the correct master password

4. **`actions.log`** (Activity Log)
   - Plain text log of all actions (no passwords stored)
   - Format: `TIMESTAMP | ACTION | WEBSITE`
   - Useful for tracking who accessed what and when
   - Example: `2025-10-31 11:39:59 | CREATE | GoogleAccount`

### Backup Files (Located in `D:\Dump\pastion\`):

The program automatically creates timestamped backups in organized subfolders:

- **`D:\Dump\pastion\vaults\`** - Encrypted vault backups
  - Format: `vault_YYYY-MM-DD_HH-MM-SS.bin`
- **`D:\Dump\pastion\master\`** - Master password hash backups
  - Format: `master_YYYY-MM-DD_HH-MM-SS.hash`
- **`D:\Dump\pastion\actions\`** - Action log backups
  - Format: `actions_YYYY-MM-DD_HH-MM-SS.log`

**Backup Management:**

- Backups are created automatically after every change
- Maximum 20 backups kept per file type (oldest deleted automatically)
- All three files (vault, master, log) share the same timestamp
- Restore any backup from the "Restore from backup" menu option

---

## 🚀 Installation & Setup

### Prerequisites:

- Python 3.7 or higher
- Windows, macOS, or Linux
- Terminal/Command Prompt access

### Step 1: Install Required Dependencies

Open your terminal and run:

```bash
pip install cryptography
```

This installs the encryption library (required for password security).

### Step 2: Install Optional Dependencies

For clipboard functionality (copy passwords with one click):

```bash
pip install pyperclip
```

**Note:** The program works without pyperclip, but you won't be able to copy passwords to clipboard.

### Step 3: Verify Installation

Check if everything is installed correctly:

```bash
python -c "import cryptography; print('✓ cryptography installed')"
python -c "import pyperclip; print('✓ pyperclip installed')"
```

### Step 4: Run the Program

Navigate to the program directory and run:

```bash
cd "d:\Resources\Vannessa Kang"
python VanessaKang.py
```

On first run, you'll be prompted to create a master password.

---

## 🎮 Program Features & Functions

### Main Menu (Interactive)

Navigate using:

- **Arrow Keys (↑/↓)** - Move up/down
- **Vim Keys (j/k)** - Alternative navigation
- **Enter** - Select option
- **ESC** - Exit

### Option 1: Create Entry 📝

**Purpose:** Add a new credential to your vault

**What You Can Store:**

- Website/Service Name (required)
- Account Email (optional)
- Username (optional)
- Phone Number (optional)
- Description (optional, max 30 words)
- Password (user-provided or auto-generated)

**Password Options:**

1. **Enter Your Own** - No validation, you decide
2. **Auto-Generate** - Creates a strong password (8-16 characters)
   - Includes: uppercase, lowercase, digits, symbols
   - Automatically meets security requirements

**Process:**

1. Enter website name
2. Fill optional fields (or skip)
3. Choose password method
4. Entry saved and encrypted automatically

**Example Usage:**

```
Website name: Gmail
Account email: john.doe@gmail.com
Username: johndoe123
Phone number: +1-555-0123
Description: Personal email account
Password: [generated or entered]
✓ Entry saved successfully!
```

---

### Option 2: Read / View Entry 🔍

**Purpose:** Search and view stored credentials

**Features:**

- Smart search (partial matching)
- Shows last 5 entries for quick access
- Master password required for security
- One-click password copying (if pyperclip installed)

**Process:**

1. Program displays your 5 most recent entries
2. Type website name (full or partial)
3. If multiple matches: choose from numbered list
4. Enter master password to unlock
5. View all details including password
6. Option to copy password to clipboard

**Display Format:**

```
╔═══════════════════════════════════════╗
║     Entry Details: Gmail              ║
╚═══════════════════════════════════════╝

  ▸ Website: Gmail
  ▸ Account: john.doe@gmail.com
  ▸ Username: johndoe123
  ▸ Phone Number: +1-555-0123
  ▸ Description: Personal email account
  ▸ Password: MySecurePassword123!

Copy password to clipboard? (y/N):
```

**Security Note:** Master password verification required every time.

---

### Option 3: Update Entry ✏️

**Purpose:** Modify existing credentials

**Navigation:** Interactive arrow-key menu (same as main menu)

**What You Can Change:**

1. Website name
2. Password (manual or generated)
3. Account email
4. Username
5. Phone number
6. Description

**Process:**

1. Search for entry (same as Option 2)
2. **Use arrow keys (↑↓) to navigate** through update options
3. Press **Enter** to select option
4. Enter new value
5. Verify with master password
6. Changes saved and encrypted

**Interactive Menu:**

```
╔══════════════════════════════════╗
║  What would you like to change?  ║
╚══════════════════════════════════╝

  ► Change website name        (highlighted with reverse color)
    Change password
    Change account
    Change username
    Change phone number
    Change description
    Cancel

  (Use ↑↓ arrows and Enter to select)
```

**Navigation Controls:**

- **↑ / ↓** - Move selection up/down
- **j / k** - Vim-style navigation (optional)
- **Enter** - Select highlighted option
- **ESC** - Cancel and return

**Special Features:**

- Generate new password option
- Email validation warning
- Description auto-truncates to 30 words
- Master password required before saving
- Visual feedback with color highlighting

---

### Option 4: Delete Entry 🗑️

**Purpose:** Permanently remove credentials

**Process:**

1. Search for entry to delete
2. View full entry details (confirmation)
3. Confirm deletion (y/N)
4. Enter master password
5. Entry permanently removed

**Display Before Deletion:**

```
╔═══════════════════════════════════════╗
║        Entry to be deleted            ║
╚═══════════════════════════════════════╝

  ▸ Website: OldAccount
  ▸ Account: old@email.com
  ▸ Username: olduser
  ▸ Phone Number: 555-0000
  ▸ Description: No longer used

Delete "OldAccount"? (y/N):
Master password: ********
✓ Entry "OldAccount" deleted successfully!
```

**Safety:** Requires both confirmation and master password.

---

### Option 5: List All Websites 📋

**Purpose:** View all stored entries with descriptions

**Display Format:**

```
╔════════════════════════════════════════════╗
║  All Stored Websites (6 entries)          ║
╚════════════════════════════════════════════╝

  WEBSITE                       │ DESCRIPTION
  ───────────────────────────── ┼ ──────────────────────
   1. Gmail                     │ Personal email account
   2. Facebook                  │ Social media login
   3. BankAccount               │ Main checking account
   4. WorkEmail                 │ Office 365 account
   5. GitHub                    │ Code repository access
   6. Netflix                   │ (no description)
```

**Features:**

- Two-column layout
- Shows website name and description
- Numbers for quick reference
- Truncates long descriptions with "..."
- Shows "(no description)" for entries without descriptions
- Responsive to terminal width

---

### Option 6: View Action Log 📊

**Purpose:** Review all activities and actions

**Log Format:**

```
╔════════════════════════════════════════════╗
║          Action Log History                ║
╚════════════════════════════════════════════╝

  TIMESTAMP           │ ACTION               │ WEBSITE
  ─────────────────── ┼ ──────────────────── ┼ ─────────
  2025-10-31 12:30:51 │ CREATE               │ Gmail
  2025-10-31 12:07:59 │ UPDATE               │ Facebook
  2025-10-31 12:15:44 │ READ                 │ BankAccount
  2025-10-31 12:20:58 │ DELETE               │ OldAccount
  2025-10-31 11:39:59 │ CHANGE_MASTER        │
  2025-10-31 11:41:35 │ READ_FAILED          │ Gmail
```

**Color Coding:**

- 🔴 **Red:** FAILED actions (incorrect password)
- 🟢 **Green:** SUCCESS, CREATE, UPDATE, SET_MASTER
- 🟡 **Yellow:** DELETE operations
- 🔵 **Cyan:** Other actions

**Logged Actions:**

- `CREATE` - New entry added
- `READ` - Entry viewed
- `READ_FAILED` - Failed to view (wrong password)
- `UPDATE` - Entry modified
- `UPDATE_FAILED` - Failed to update
- `DELETE` - Entry removed
- `DELETE_FAILED` - Failed to delete
- `SET_MASTER` - Master password created
- `CHANGE_MASTER` - Master password changed
- `CHANGE_MASTER_FAILED` - Failed password change
- `CLEAR_LOG` - Log entries cleared
- `RESTORE_SUCCESS` - Backup restored
- `RESTORE_FAILED` - Restore failed

---

### Option 7: Clear Action Log 🧹

**Purpose:** Remove old log entries to save space

**New Flexible System:**

```
Total log entries: 25

Clear Options:
  • Enter a number (1-25) to clear that many oldest entries
  • Enter 0 to clear ALL entries
  • Press Ctrl+C to cancel

Number of oldest entries to clear (0 for all): _
```

**How It Works:**

1. Shows total number of log entries
2. Enter any number to clear that many oldest entries
3. Enter 0 to clear everything
4. Confirms before clearing
5. Requires master password verification
6. Deletes from oldest to newest

**Examples:**

- Enter `5` → Clears 5 oldest entries, keeps the rest
- Enter `10` → Clears 10 oldest entries
- Enter `0` → Clears all 25 entries
- Enter `50` (but only 25 exist) → Offers to clear all

**Safety:** Always requires master password.

---

### Option 8: Restore from Backup 🔄

**Purpose:** Restore vault from previous backups

**Navigation:** Interactive arrow-key selection (same as main menu)

**Display Format:**

```
╔════════════════════════════════════════════╗
║        Restore From Backup                 ║
╚════════════════════════════════════════════╝

⚠ Warning: This will replace your current files!

  #    TIMESTAMP            │ ACTION
  ───  ──────────────────── ┼ ──────────────────────────
► 1.  2025-10-31 12:30:51  │ CREATE GoogleAccount      (highlighted)
  2.  2025-10-31 12:07:59  │ UPDATE Facebook
  3.  2025-10-31 12:15:44  │ DELETE OldAccount
  4.  2025-10-31 12:20:58  │ SET_MASTER
  5.  2025-10-31 11:39:59  │ CREATE Github

  (Use ↑↓ arrows and Enter to select, or 0 to cancel)
```

**Navigation Controls:**

- **↑ / ↓** - Move selection up/down through backups
- **j / k** - Vim-style navigation (optional)
- **Enter** - Select highlighted backup to restore
- **0** - Cancel and return to main menu
- **ESC** - Cancel and return

**Action Column Details:**

- Shows **action + website name** for context
- Examples:
  - `CREATE GoogleAccount` - Account created
  - `UPDATE Facebook` - Password updated
  - `DELETE OldAccount` - Entry removed
  - `SET_MASTER` - Master password set/changed
  - `READ Github` - Entry viewed

**Color Coding:**

- 🟢 **Green** - CREATE, UPDATE, SUCCESS, SET_MASTER
- 🔵 **Cyan** - READ, BACKUP
- 🟡 **Yellow** - DELETE, CLEAR_LOG
- 🔴 **Red** - FAILED actions

**Features:**

- Shows last 15 backups with full context
- Displays what action triggered each backup
- Interactive selection with visual feedback
- Shows which files are available in backup

**Process:**

1. **Navigate** with arrow keys to select backup
2. Press **Enter** to select
3. View available files (✓ or ✗)
   - ✓ Vault
   - ✓ Master
   - ✓ Log
4. Enter master password to verify
5. Confirm restore (data will be lost!)
6. Program restarts with restored data

**Important:** Restoring requires program restart.

---

### Option 9: Change Master Password 🔑

**Purpose:** Update your master password

**Process:**

1. Enter current master password
2. Enter new master password
3. Repeat new password (must match)
4. Password strength validation
5. If weak: option to auto-generate
6. Vault re-encrypted with new password
7. Backup created automatically

**Password Requirements:**

- At least 8 characters
- Contains uppercase letters
- Contains lowercase letters
- Contains digits
- Contains symbols

**Important:** Changing master password re-encrypts your entire vault!

---

### Option C: Clear Terminal 🧼

**Purpose:** Clear the terminal screen for privacy

**How to Use:**

- Press `c` or `C` in the main menu
- Screen clears immediately
- Menu reappears
- No data lost

**Use Cases:**

- Someone walking by
- Screenshots/screen sharing
- General privacy
- Clean workspace

---

### Option 0: Exit 🚪

**Purpose:** Safely close the program

**What Happens:**

- Saves all data automatically
- Creates backup if changes made
- Displays goodbye message
- Program terminates

**No data loss:** Everything is auto-saved throughout your session.

---

## 🔒 Security Features

### Encryption Details

**Algorithm:** AES-256 via Fernet (symmetric encryption)

- **Key Derivation:** PBKDF2-HMAC-SHA256
- **Iterations:** 390,000 (OWASP recommended)
- **Salt:** 16 random bytes per encryption
- **Key Length:** 32 bytes (256 bits)

**What This Means:**

- Your passwords are encrypted with military-grade security
- Even if someone steals `vault.bin`, they can't read it without your master password
- Each encryption uses a unique salt (even with same password)
- Would take billions of years to crack with current technology

### Master Password Protection

**Storage Method:**

1. Master password is never stored in plain text
2. Password is hashed with PBKDF2 (390,000 iterations)
3. 16-byte random salt generated
4. Hash + salt stored in `master.hash`
5. Verification token encrypted and stored

**Brute Force Protection:**

- Maximum 3 failed login attempts
- After 3 failures: program exits
- Must restart program to try again
- No lockout period (but manual restart required)

**Example:**

```
Master password: ******** (wrong)
Incorrect master password.

Master password: ******** (wrong)
Incorrect master password.

Master password: ******** (wrong)
Incorrect master password.

Too many failed attempts. Exiting.
```

### Session Security

**Auto-Timeout Feature:**

- 90-minute inactivity timer
- Automatic logout if no interaction
- Protects against unauthorized access
- Timer resets with any action

**Example:**

```
Session timed out due to inactivity (90 minutes).
Exiting for security.
```

### File Permissions

**Important:**

- Keep `master.hash` secret and secure
- Never share `vault.bin` publicly
- `actions.log` is plain text (no passwords stored)
- Consider encrypting your backup directory

---

## ⚠️ Critical Security Scenarios

### What if I delete `master.hash`?

**Consequence:** You will lose access to all your passwords permanently.

**What Happens:**

1. Program detects missing `master.hash`
2. Treats you as a new user
3. Asks you to create a new master password
4. Creates new `master.hash` file
5. Your old `vault.bin` becomes **UNREADABLE**

**Why?**

- The vault is encrypted with a key derived from your original master password
- Without the original `master.hash`, there's no way to verify or derive the correct key
- Even if you remember your old password, the specific hash and salt are lost

**Prevention:**

- ✅ Regularly backup `master.hash` to a secure location
- ✅ Use the built-in backup system
- ✅ Store a copy on USB drive or cloud (encrypted)
- ✅ Never delete unless absolutely sure

### What if I delete `vault.bin`?

**Consequence:** You lose all your stored passwords.

**What Happens:**

1. Program creates a new empty `vault.bin`
2. All your credentials are gone
3. Master password still works
4. You start fresh

**Recovery:**

- Restore from backup (Option 8)
- Backup files in `D:\Dump\pastion\vaults\`

### What if I delete `actions.log`?

**Consequence:** You lose your activity history only.

**What Happens:**

1. Log file recreated automatically
2. No passwords lost
3. Previous activities not visible
4. Fresh log starts

**Impact:** Minimal - just historical data lost.

### What if I forget my master password?

**Consequence:** There is NO recovery option.

**Reality:**

- No password reset feature (by design)
- No "forgot password" option
- No backdoor access
- This is a security feature, not a bug

**Options:**

1. Try all passwords you might have used
2. Restore from backup (if you can log in to another backup)
3. Last resort: Delete `master.hash` and `vault.bin`, start fresh

**Prevention:**

- Write down master password in a safe place
- Use a memorable but strong passphrase
- Store securely (not digitally)

### What if someone gets my `vault.bin`?

**Impact:** Your passwords are safe.

**Reason:**

- File is encrypted with AES-256
- Requires master password to decrypt
- No master password = no access
- Cracking would take billions of years

**But they could:**

- Delete your vault (destructive)
- Copy it (but can't read it)

**Prevention:**

- Keep backups
- Secure your computer
- Use full-disk encryption

### What if I move the files?

**Relocating Files:**

**Option 1:** Move everything together

```
✓ VanessaKang.py
✓ master.hash
✓ vault.bin
✓ actions.log
```

Keep all files in same directory - program will work.

**Option 2:** Update backup path

- Edit `BACKUP_DIR` variable in `VanessaKang.py`
- Line ~60: `BACKUP_DIR = r'D:\Dump\pastion'`
- Change to your new backup location

**Important:** Don't separate `master.hash` from `vault.bin`!

---

## 🛠️ Troubleshooting

### Common Issues:

**1. "Module 'cryptography' not found"**

```bash
pip install cryptography
```

**2. "Module 'pyperclip' not found"**

- Either install: `pip install pyperclip`
- Or ignore (copy function won't work but program runs)

**3. "Permission denied" on backup folder**

- Check backup folder exists: `D:\Dump\pastion`
- Create it manually if needed
- Or change `BACKUP_DIR` in code

**4. "Unable to decrypt vault"**

- Wrong master password entered
- Or `vault.bin` corrupted
- Try restore from backup (Option 8)

**5. Terminal colors not showing**

- Use a modern terminal (Windows Terminal, iTerm2, etc.)
- Command Prompt may not support all colors
- Update your terminal emulator

**6. Box characters look weird (�)**

- Terminal doesn't support UTF-8
- Use Windows Terminal or update terminal
- Check terminal encoding settings

---

## 📝 Best Practices

### Do's ✅

1. **Backup Regularly**

   - Automatic backups are created
   - Manually copy backup folder occasionally
   - Store on different drive/cloud

2. **Use Strong Master Password**

   - At least 12 characters
   - Mix of letters, numbers, symbols
   - Memorable but complex
   - Write it down in a safe place

3. **Keep Files Together**

   - All files in same directory
   - Don't separate them

4. **Review Action Log**

   - Check for suspicious activity
   - Verify your own actions
   - Clear old entries periodically

5. **Use Descriptions**
   - Add descriptions to entries
   - Makes searching easier
   - Helps remember account purposes

### Don'ts ❌

1. **Never Share**

   - `master.hash` file
   - Your master password
   - `vault.bin` file

2. **Don't Use Weak Master Password**

   - No "password123"
   - No birthdays or names
   - No common words

3. **Don't Store Plain Text**

   - Don't write passwords in `actions.log`
   - Don't take screenshots of passwords
   - Don't paste into unsecure places

4. **Don't Ignore Security**

   - Don't leave terminal open
   - Don't share screen while using
   - Don't use on public computers

5. **Don't Modify Files Manually**
   - Don't edit `vault.bin`
   - Don't edit `master.hash`
   - Use program functions only

---

## 🎨 Interface Guide

### Color Meanings:

- 🔵 **Cyan** - Headers, borders, numbers, primary color
- 🟢 **Green** - Success messages, passwords, positive actions
- 🟡 **Yellow** - Warnings, accounts, caution needed
- 🔴 **Red** - Errors, failures, destructive actions
- 🟣 **Magenta** - Usernames
- 🔷 **Blue** - Phone numbers
- ⚫ **Gray** - Descriptions, timestamps, secondary info
- ⚪ **Bold** - Important text, emphasis

### Symbols Used:

- ✓ - Success
- ✗ - Failure/Missing
- ⚠ - Warning
- ► - Selected menu item
- ▸ - List item bullet
- │ - Column separator
- ┼ - Column junction
- ─ - Horizontal line
- ╔╗╚╝ - Box corners
- ═║ - Bold borders

---

## 📞 Support & Contributions

### Need Help?

If you encounter issues:

1. Check Troubleshooting section above
2. Review error messages carefully
3. Check if all dependencies installed
4. Try restore from backup

### Want to Contribute?

This is a personal project by Ream Daly. If you want to improve it:

- Add features you need
- Fix bugs you find
- Enhance security
- Improve UI/UX

### Attribution

If you use or modify this project:

- Credit: Ream Daly
- Project: Vanessa Kang
- Date: October 2025

---

## 📜 License & Disclaimer

**Created by:** Ream Daly  
**Date:** October 23-31, 2025

**Disclaimer:**

- This software is provided "as is"
- No warranty for data loss or security breaches
- User responsible for backups and security
- Not liable for forgotten passwords
- Use at your own risk

**Security Notice:**
While this program uses military-grade encryption (AES-256), no software is 100% secure. Always:

- Keep your system secure
- Use strong master password
- Maintain backups
- Be cautious with sensitive data

---

## 🎓 Technical Details

### Dependencies:

```python
# Required
import cryptography  # Encryption (Fernet, PBKDF2)

# Optional
import pyperclip     # Clipboard functionality

# Built-in (no installation needed)
import os, json, sys, base64
import secrets, string, datetime
import msvcrt, time, shutil
```

### Encryption Workflow:

1. **Master Password → Key**

   ```
   Password → PBKDF2(390k iterations) → 32-byte key
   ```

2. **Data Encryption**

   ```
   Vault Data → JSON → UTF-8 → Fernet(AES-256) → vault.bin
   ```

3. **Master Password Storage**
   ```
   Password → PBKDF2 → Hash + Salt → master.hash
   Verification token encrypted and stored
   ```

### File Formats:

**master.hash:**

```
[16 bytes salt]--[encrypted verification token]
```

**vault.bin:**

```
[16 bytes salt]--[encrypted JSON data]
```

**actions.log:**

```
YYYY-MM-DD HH:MM:SS | ACTION | WEBSITE
```

---

## 🚀 Quick Start Guide

**For First-Time Users:**

1. Install Python 3.7+
2. Run: `pip install cryptography pyperclip`
3. Run: `python VanessaKang.py`
4. Create master password (remember it!)
5. Start adding your credentials

**Daily Usage:**

1. Run program
2. Enter master password
3. Choose action from menu
4. Manage your passwords
5. Exit when done (auto-saves)

---

## 📊 Statistics

**Program Metrics:**

- Lines of Code: ~1,400+
- Functions: 30+
- Menu Options: 11
- Supported Fields: 6 per entry
- Color Themes: 8
- Security Iterations: 390,000
- Auto-Backup: Every change
- Max Backups Kept: 20 per file
- Session Timeout: 90 minutes
- Login Attempts: 3 max

---

## 🎉 Final Notes

**Vanessa Kang** is designed to be:

- Secure (military-grade encryption)
- User-friendly (colorful interface)
- Feature-rich (11 menu options)
- Reliable (auto-backups)
- Safe (brute force protection)

**Remember:**

- Your master password is the key to everything
- Backups are your safety net
- Action logs help you track activity
- The program is as secure as your master password

**Stay Secure! 🔒**

---

_README.md created by Ream Daly | Vanessa Kang v2.0 | October 2025_
