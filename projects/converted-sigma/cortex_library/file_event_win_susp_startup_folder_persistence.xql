// Title: Suspicious Startup Folder Persistence
// ID: 28208707-fe31-437f-9a7f-4b1108b94d2e
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2022-08-10
// Tags: attack.privilege-escalation, attack.execution, attack.t1204.002, attack.persistence, attack.t1547.001
// Description: Detects the creation of potentially malicious script and executable files in Windows startup folders, which is a common persistence technique used by threat actors.
// These files (.ps1, .vbs, .js, .bat, etc.) are automatically executed when a user logs in, making the Startup folder an attractive target for attackers.
// This technique is frequently observed in malvertising campaigns and malware distribution where attackers attempt to maintain long-term access to compromised systems.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_file_path contains "\\Windows\\Start Menu\\Programs\\Startup\\" and (action_file_path endswith ".bat" or action_file_path endswith ".cmd" or action_file_path endswith ".dll" or action_file_path endswith ".hta" or action_file_path endswith ".jar" or action_file_path endswith ".js" or action_file_path endswith ".jse" or action_file_path endswith ".msi" or action_file_path endswith ".ps1" or action_file_path endswith ".psd1" or action_file_path endswith ".psm1" or action_file_path endswith ".scr" or action_file_path endswith ".url" or action_file_path endswith ".vba" or action_file_path endswith ".vbe" or action_file_path endswith ".vbs" or action_file_path endswith ".wsf"))
