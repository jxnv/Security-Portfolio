// Title: Potential Startup Shortcut Persistence Via PowerShell.EXE
// ID: 92fa78e7-4d39-45f1-91a3-8b23f3f1088d
// Status: test
// Level: high
// Author: Christopher Peacock '@securepeacock', SCYTHE
// Date: 2021-10-24
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
// Description: Detects PowerShell writing startup shortcuts.
// This procedure was highlighted in Red Canary Intel Insights Oct. 2021, "We frequently observe adversaries using PowerShell to write malicious .lnk files into the startup directory to establish persistence.
// Accordingly, this detection opportunity is likely to identify persistence mechanisms in multiple threats.
// In the context of Yellow Cockatoo, this persistence mechanism eventually launches the command-line script that leads to the installation of a malicious DLL"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe") and action_file_path contains "\\start menu\\programs\\startup\\" and action_file_path endswith ".lnk")
