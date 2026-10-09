// Title: Execute Code with Pester.bat as Parent
// ID: 18988e1b-9087-4f8a-82fe-0414dce49878
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali
// Date: 2022-08-20
// Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1216
// Description: Detects code execution via Pester.bat (Pester - Powershell Modulte for testing)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_command_line contains "{ Invoke-Pester -EnableExit ;" or actor_process_command_line contains "{ Get-Help \"")) and ((actor_process_image_path endswith "\\powershell.exe" or actor_process_image_path endswith "\\pwsh.exe") and actor_process_command_line contains "\\WindowsPowerShell\\Modules\\Pester\\"))
