// Title: Potential CommandLine Obfuscation Using Unicode Characters From Suspicious Image
// ID: 584bca0f-3608-4402-80fd-4075ff6072e3
// Status: test
// Level: high
// Author: frack113, Florian Roth (Nextron Systems), Josh Nickels
// Date: 2024-09-02
// Tags: attack.stealth, attack.t1027
// Description: Detects potential commandline obfuscation using unicode characters.
// Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\wscript.exe") and (action_process_image_name = "Cmd.EXE" or action_process_image_name = "cscript.exe" or action_process_image_name = "PowerShell.EXE" or action_process_image_name = "PowerShell_ISE.EXE" or action_process_image_name = "pwsh.dll" or action_process_image_name = "wscript.exe")) and ((action_process_image_command_line contains "ˣ" or action_process_image_command_line contains "˪" or action_process_image_command_line contains "ˢ" or action_process_image_command_line contains "∕" or action_process_image_command_line contains "⁄" or action_process_image_command_line contains "―" or action_process_image_command_line contains "—" or action_process_image_command_line contains " " or action_process_image_command_line contains "¯" or action_process_image_command_line contains "®" or action_process_image_command_line contains "¶" or action_process_image_command_line contains "⠀")))
