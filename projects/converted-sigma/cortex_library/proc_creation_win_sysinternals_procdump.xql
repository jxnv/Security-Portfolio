// Title: Procdump Execution
// ID: 2e65275c-8288-4ab4-aeb7-6274f58b6b20
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2021-08-16
// Tags: attack.stealth, attack.t1036, attack.t1003.001, attack.credential-access
// Description: Detects usage of the SysInternals Procdump utility
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\procdump.exe" or action_process_image_path endswith "\\procdump64.exe" or action_process_image_path endswith "\\procdump64a.exe"))
