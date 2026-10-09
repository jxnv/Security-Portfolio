// Title: Potential Suspicious Browser Launch From Document Reader Process
// ID: 1193d960-2369-499f-a158-7b50a31df682
// Status: test
// Level: medium
// Author: Joseph Kamau
// Date: 2024-05-27
// Tags: attack.execution, attack.t1204.002
// Description: Detects when a browser process or browser tab is launched from an application that handles document files such as Adobe, Microsoft Office, etc. And connects to a web application over http(s), this could indicate a possible phishing attempt.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_image_path contains "Acrobat Reader" or actor_process_image_path contains "Microsoft Office" or actor_process_image_path contains "PDF Reader") and (action_process_image_path endswith "\\brave.exe" or action_process_image_path endswith "\\chrome.exe" or action_process_image_path endswith "\\firefox.exe" or action_process_image_path endswith "\\msedge.exe" or action_process_image_path endswith "\\opera.exe" or action_process_image_path endswith "\\maxthon.exe" or action_process_image_path endswith "\\seamonkey.exe" or action_process_image_path endswith "\\vivaldi.exe") and action_process_image_command_line contains "http") and not ((action_process_image_command_line contains "https://go.microsoft.com/fwlink/")) and not (((action_process_image_command_line contains "http://ad.foxitsoftware.com/adlog.php?" or action_process_image_command_line contains "https://globe-map.foxitservice.com/go.php?do=redirect"))))
