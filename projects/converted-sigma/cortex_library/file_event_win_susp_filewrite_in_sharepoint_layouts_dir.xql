// Title: Suspicious File Write to SharePoint Layouts Directory
// ID: 1f0489be-b496-4ddf-b3a9-5900f2044e9c
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-07-24
// Tags: attack.initial-access, attack.t1190, attack.persistence, attack.t1505.003
// Description: Detects suspicious file writes to SharePoint layouts directory which could indicate webshell activity or post-exploitation.
// This behavior has been observed in the exploitation of SharePoint vulnerabilities such as CVE-2025-49704, CVE-2025-49706 or CVE-2025-53770.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\w3wp.exe") and (action_file_path startswith "C:\\Program Files\\Common Files\\Microsoft Shared\\Web Server Extensions\\" or action_file_path startswith "C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\Web Server Extensions\\") and (action_file_path contains "\\15\\TEMPLATE\\LAYOUTS\\" or action_file_path contains "\\16\\TEMPLATE\\LAYOUTS\\") and (action_file_path endswith ".asax" or action_file_path endswith ".ascx" or action_file_path endswith ".ashx" or action_file_path endswith ".asmx" or action_file_path endswith ".asp" or action_file_path endswith ".aspx" or action_file_path endswith ".bat" or action_file_path endswith ".cmd" or action_file_path endswith ".cer" or action_file_path endswith ".config" or action_file_path endswith ".hta" or action_file_path endswith ".js" or action_file_path endswith ".jsp" or action_file_path endswith ".jspx" or action_file_path endswith ".php" or action_file_path endswith ".ps1" or action_file_path endswith ".vbs"))
