// Title: Suspicious Service Binary Directory
// ID: 883faa95-175a-4e22-8181-e5761aeb373c
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-03-09
// Tags: attack.stealth, attack.t1202
// Description: Detects a service binary running in a suspicious directory
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path contains "\\Users\\Public\\" or action_process_image_path contains "\\$Recycle.bin" or action_process_image_path contains "\\Users\\All Users\\" or action_process_image_path contains "\\Users\\Default\\" or action_process_image_path contains "\\Users\\Contacts\\" or action_process_image_path contains "\\Users\\Searches\\" or action_process_image_path contains "C:\\Perflogs\\" or action_process_image_path contains "\\config\\systemprofile\\" or action_process_image_path contains "\\Windows\\Fonts\\" or action_process_image_path contains "\\Windows\\IME\\" or action_process_image_path contains "\\Windows\\addins\\") and (actor_process_image_path endswith "\\services.exe" or actor_process_image_path endswith "\\svchost.exe"))
