// Title: Potentially Suspicious GoogleUpdate Child Process
// ID: 84b1ecf9-6eff-4004-bafb-bae5c0e251b2
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-15
// Tags: attack.stealth
// Description: Detects potentially suspicious child processes of "GoogleUpdate.exe"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\GoogleUpdate.exe") and not (((action_process_image_path = null) or ((action_process_image_path contains "\\Google") or ((action_process_image_path endswith "\\setup.exe" or action_process_image_path endswith "chrome_updater.exe" or action_process_image_path endswith "chrome_installer.exe"))))))
