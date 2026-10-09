// Title: Suspicious Non-Browser Network Communication With Telegram API
// ID: c3dbbc9f-ef1d-470a-a90a-d343448d5875
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-19
// Tags: attack.command-and-control, attack.exfiltration, attack.t1102, attack.t1567, attack.t1105
// Description: Detects an a non-browser process interacting with the Telegram API which could indicate use of a covert C2
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((DestinationHostname contains "api.telegram.org") and not (((action_process_image_path endswith "\\brave.exe") or ((action_process_image_path = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" or action_process_image_path = "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe")) or ((action_process_image_path startswith "C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\") or (action_process_image_path endswith "\\WindowsApps\\MicrosoftEdge.exe") or ((action_process_image_path = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" or action_process_image_path = "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"))) or ((action_process_image_path startswith "C:\\Program Files (x86)\\Microsoft\\EdgeCore\\" or action_process_image_path startswith "C:\\Program Files\\Microsoft\\EdgeCore\\") and (action_process_image_path endswith "\\msedge.exe" or action_process_image_path endswith "\\msedgewebview2.exe")) or ((action_process_image_path = "C:\\Program Files\\Mozilla Firefox\\firefox.exe" or action_process_image_path = "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe")) or ((action_process_image_path = "C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe" or action_process_image_path = "C:\\Program Files\\Internet Explorer\\iexplore.exe")) or (action_process_image_path endswith "\\maxthon.exe") or (action_process_image_path endswith "\\opera.exe") or (action_process_image_path endswith "\\safari.exe") or (action_process_image_path endswith "\\seamonkey.exe") or (action_process_image_path endswith "\\vivaldi.exe") or (action_process_image_path endswith "\\whale.exe"))))
