// Title: Suspicious File Created Via OneNote Application
// ID: fcc6d700-68d9-4241-9a1a-06874d621b06
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-09
// Tags: attack.stealth
// Description: Detects suspicious files created via the OneNote application. This could indicate a potential malicious ".one"/".onepkg" file was executed as seen being used in malware activity in the wild
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\onenote.exe" or action_process_image_path endswith "\\onenotem.exe" or action_process_image_path endswith "\\onenoteim.exe") and action_file_path contains "\\AppData\\Local\\Temp\\OneNote\\" and (action_file_path endswith ".bat" or action_file_path endswith ".chm" or action_file_path endswith ".cmd" or action_file_path endswith ".dll" or action_file_path endswith ".exe" or action_file_path endswith ".hta" or action_file_path endswith ".htm" or action_file_path endswith ".html" or action_file_path endswith ".js" or action_file_path endswith ".lnk" or action_file_path endswith ".ps1" or action_file_path endswith ".vbe" or action_file_path endswith ".vbs" or action_file_path endswith ".wsf"))
