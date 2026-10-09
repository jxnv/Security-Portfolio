// Title: Delete Defender Scan ShellEx Context Menu Registry Key
// ID: 72a0369a-2576-4aaf-bfc9-6bb24a574ac6
// Status: experimental
// Level: medium
// Author: Matt Anderson (Huntress)
// Date: 2025-07-11
// Tags: attack.defense-impairment
// Description: Detects deletion of registry key that adds 'Scan with Defender' option in context menu. Attackers may use this to make it harder for users to scan files that are suspicious.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "shellex\\ContextMenuHandlers\\EPP") and not (((action_process_image_path startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\" or action_process_image_path startswith "C:\\Program Files\\Windows Defender\\" or action_process_image_path startswith "C:\\Program Files (x86)\\Windows Defender\\") and action_process_image_path endswith "\\MsMpEng.exe")))
