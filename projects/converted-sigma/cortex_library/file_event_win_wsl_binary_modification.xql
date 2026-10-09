// Title: Potential WSL Binary Modification from Installed Location
// ID: 2f400434-01e1-416b-b52c-bb5bfbb9eb78
// Status: experimental
// Level: medium
// Author: Liran Ravich, Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-05-05
// Tags: attack.stealth, attack.t1036.005, attack.t1218
// Description: Detects the modification of the wsl.exe binary from its installed location.
// Attackers can replace the legitimate wsl.exe binary with a malicious payload in its place, which is then executed when the user runs WSL, acting as a proxy execution and defense evasion technique.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_file_path endswith "\\wsl.exe") and (((action_file_path contains ":\\Program files\\wsl\\" or action_file_path contains ":\\Program files\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux_")) or ((action_file_path contains ":\\Users\\" and action_file_path contains "\\AppData\\Local\\Microsoft\\WindowsApps\\")))) and not ((((action_process_image_path = "C:\\Windows\\System32\\msiexec.exe" or action_process_image_path = "C:\\Windows\\SysWOW64\\msiexec.exe")) or (action_process_image_path = "C:\\Windows\\System32\\svchost.exe" and action_file_path contains "\\WindowsApps\\"))))
