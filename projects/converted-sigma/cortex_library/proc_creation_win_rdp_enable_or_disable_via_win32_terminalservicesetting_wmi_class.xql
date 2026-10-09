// Title: RDP Enable or Disable via Win32_TerminalServiceSetting WMI Class
// ID: 4b8f6d3a-9c5e-4f2a-a7d8-6b9c3e5f2a8d
// Status: experimental
// Level: medium
// Author: Daniel Koifman (KoifSec), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-11-15
// Tags: attack.lateral-movement, attack.t1021.001, attack.execution, attack.t1047
// Description: Detects enabling or disabling of Remote Desktop Protocol (RDP) using alternate methods such as WMIC or PowerShell.
// In PowerShell one-liner commands, the "SetAllowTSConnections" method of the "Win32_TerminalServiceSetting" class may be used to enable or disable RDP.
// In WMIC, the "rdtoggle" alias or "Win32_TerminalServiceSetting" class may be used for the same purpose.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "rdtoggle" or action_process_image_command_line contains "Win32_TerminalServiceSetting")) and (action_process_image_command_line contains "SetAllowTSConnections") and (((action_process_image_path endswith "\\wmic.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "wmic.exe" or action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))))
