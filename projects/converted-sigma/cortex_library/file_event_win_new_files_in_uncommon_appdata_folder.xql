// Title: Suspicious File Creation In Uncommon AppData Folder
// ID: d7b50671-d1ad-4871-aa60-5aa5b331fe04
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-05
// Tags: attack.execution, attack.stealth
// Description: Detects the creation of suspicious files and folders inside the user's AppData folder but not inside any of the common and well known directories (Local, Romaing, LocalLow). This method could be used as a method to bypass detection who exclude the AppData folder in fear of FPs
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path startswith "C:\\Users\\" and action_file_path contains "\\AppData\\" and (action_file_path endswith ".bat" or action_file_path endswith ".cmd" or action_file_path endswith ".cpl" or action_file_path endswith ".dll" or action_file_path endswith ".exe" or action_file_path endswith ".hta" or action_file_path endswith ".iso" or action_file_path endswith ".lnk" or action_file_path endswith ".msi" or action_file_path endswith ".ps1" or action_file_path endswith ".psm1" or action_file_path endswith ".scr" or action_file_path endswith ".vbe" or action_file_path endswith ".vbs")) and not ((action_file_path startswith "C:\\Users\\" and (action_file_path contains "\\AppData\\Local\\" or action_file_path contains "\\AppData\\LocalLow\\" or action_file_path contains "\\AppData\\Roaming\\"))))
