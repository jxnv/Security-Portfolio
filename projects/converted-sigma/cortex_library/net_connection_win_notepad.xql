// Title: Network Connection Initiated Via Notepad.EXE
// ID: e81528db-fc02-45e8-8e98-4e84aba1f10b
// Status: test
// Level: high
// Author: EagleEye Team
// Date: 2020-05-14
// Tags: attack.privilege-escalation, attack.command-and-control, attack.execution, attack.stealth, attack.t1055
// Description: Detects a network connection that is initiated by the "notepad.exe" process.
// This might be a sign of process injection from a beacon process or something similar.
// Notepad rarely initiates a network communication except when printing documents for example.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\notepad.exe") and not ((action_remote_port = 9100)))
