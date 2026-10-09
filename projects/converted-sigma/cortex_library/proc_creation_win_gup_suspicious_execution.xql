// Title: Suspicious GUP Usage
// ID: 0a4f6091-223b-41f6-8743-f322ec84930b
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2019-02-06
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects execution of the Notepad++ updater in a suspicious directory, which is often used in DLL side-loading attacks
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\GUP.exe") and not ((((action_process_image_path endswith "\\Program Files\\Notepad++\\updater\\GUP.exe" or action_process_image_path endswith "\\Program Files (x86)\\Notepad++\\updater\\GUP.exe")) or (action_process_image_path contains "\\Users\\" and (action_process_image_path endswith "\\AppData\\Local\\Notepad++\\updater\\GUP.exe" or action_process_image_path endswith "\\AppData\\Roaming\\Notepad++\\updater\\GUP.exe")))))
