// Title: Always Install Elevated MSI Spawned Cmd And Powershell
// ID: 1e53dd56-8d83-4eb4-a43e-b790a05510aa
// Status: test
// Level: medium
// Author: Teymur Kheirkhabarov (idea), Mangatas Tondang (rule), oscd.community
// Date: 2020-10-13
// Tags: attack.privilege-escalation, attack.t1548.002
// Description: Detects Windows Installer service (msiexec.exe) spawning "cmd" or "powershell"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "Cmd.Exe" or action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))) and ((actor_process_image_path contains "\\Windows\\Installer\\" and actor_process_image_path contains "msi") and actor_process_image_path endswith "tmp"))
