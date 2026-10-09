// Title: Credential Manager Access By Uncommon Applications
// ID: 407aecb1-e762-4acf-8c7b-d087bcff3bb6
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-11
// Tags: attack.t1003, attack.credential-access
// Description: Detects suspicious processes based on name and location that access the windows credential manager and vault.
// Which can be a sign of credential stealing. Example case would be usage of mimikatz "dpapi::cred" function
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((FileName contains "\\AppData\\Local\\Microsoft\\Credentials\\" or FileName contains "\\AppData\\Roaming\\Microsoft\\Credentials\\" or FileName contains "\\AppData\\Local\\Microsoft\\Vault\\" or FileName contains "\\ProgramData\\Microsoft\\Vault\\")) and not (((action_process_image_path = "C:\\Windows\\explorer.exe") or ((action_process_image_path startswith "C:\\Program Files\\" or action_process_image_path startswith "C:\\Program Files (x86)\\" or action_process_image_path startswith "C:\\Windows\\system32\\" or action_process_image_path startswith "C:\\Windows\\SysWOW64\\")))))
