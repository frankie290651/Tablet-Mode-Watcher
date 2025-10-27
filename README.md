# Tablet Mode Watcher

Tablet Mode Watcher is a utility that makes Windows switch between slate and tablet mode when the keyboard is detached or attached.  
NOTE: This tool was developed specifically for the Asus PZ13 and requires administrator privileges.

Status: Stable

## Requirements
- .NET 9 Framework (runtime)
- Windows (tested on Asus PZ13)
- Administrator privileges for installation and automatic startup configuration

## Installation
1. Determine the PID and VID to put into `watcher.config.json`:
   - Open Device Manager while the keyboard is connected.
   - Note the PID and VID for devices listed under Keyboards.
   - Disconnect the keyboard.
   - Identify which device entry disappeared and use its PID and VID.
   - Add those PID and VID values to `watcher.config.json`.

2. Run the installer script as an administrator:
   - Using the GUI: right-click `install-TabletModeWatcher.ps1` → "Run as administrator".
   - Using PowerShell (example that launches an elevated PowerShell to run the script):
   ```powershell
   Start-Process powershell -Verb runAs -ArgumentList "-ExecutionPolicy Bypass -File `\"install-TabletModeWatcher.ps1`\""
   ```

The `install-TabletModeWatcher.ps1` script should configure the application to run at logon (for example by installing a service or setting an autorun entry).

## Usage
- No manual start command is needed. Once installed, the program runs automatically at user logon.
- Installation and initial configuration require an account with administrator rights.

## Important files
- `install-TabletModeWatcher.ps1` — installation script (run as admin).
- `watcher.config.json` — configuration file where you put the device PID/VID.
- `src/` — C# source code (if present).
- `README.md`, `LICENSE`, `.gitignore` — project documentation and ignore rules.

## Testing
- There are no automated tests included. If you want to add tests (e.g., xUnit), tell me which test framework you prefer and I can add an example and instructions.

## License
This project is released under the MIT License. See the `LICENSE` file for details.

## Contact
Author: frankie290651