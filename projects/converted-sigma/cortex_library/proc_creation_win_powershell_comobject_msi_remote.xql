// Title: PowerShell MSI Install via WindowsInstaller COM From Remote Location
// ID: 222720a7-047f-4054-baa5-bab9be757db0
// Status: experimental
// Level: medium
// Author: Meroujan Antonyan (vx3r)
// Date: 2025-06-05
// Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1218, attack.command-and-control, attack.t1105
// Description: Detects the execution of PowerShell commands that attempt to install MSI packages via the
// Windows Installer COM object (`WindowsInstaller.Installer`) hosted remotely.
// This could be indication of malicious software deployment or lateral movement attempts using Windows Installer functionality.
// And the usage of WindowsInstaller COM object rather than msiexec could be an attempt to bypass the detection.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "-ComObject" and action_process_image_command_line contains "InstallProduct(")) and (((action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell_ISE.EXE" or action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))) and ((action_process_image_command_line contains "http" or action_process_image_command_line contains "\\\\\\\\"))) and not (((action_process_image_command_line contains "://127.0.0.1" or action_process_image_command_line contains "://localhost"))))
