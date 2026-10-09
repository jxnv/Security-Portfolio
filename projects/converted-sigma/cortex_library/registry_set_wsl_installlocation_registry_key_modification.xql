// Title: Potential WSL InstallLocation Registry Key Modification
// ID: 83475063-b1c8-4774-9568-69bbda71a539
// Status: experimental
// Level: medium
// Author: Liran Ravich, Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-05-05
// Tags: attack.stealth, attack.defense-impairment, attack.persistence, attack.t1112, attack.t1218
// Description: Detects modifications to the Windows Subsystem for Linux (WSL) InstallLocation registry key.
// Attackers can modify this registry key to redirect the execution flow of legitimate WSL processes (wsl.exe or bash.exe) to a malicious payload, acting as a proxy execution and defense evasion technique.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\Lxss\\MSI\\InstallLocation") and not (((((Details = "C:\\Program Files\\WSL" or Details = "%ProgramFiles%\\WSL")) or ((Details contains ":\\Program Files\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux_" or Details contains "\\AppData\\Local\\Microsoft\\WindowsApps" or Details contains "%ProgramFiles%\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux_"))) or ((action_process_image_path = "C:\\Windows\\System32\\msiexec.exe" or action_process_image_path = "C:\\Windows\\SysWOW64\\msiexec.exe")))))
