// Title: .RDP File Created By Uncommon Application
// ID: fccfb43e-09a7-4bd2-8b37-a5a7df33386d
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-18
// Tags: attack.stealth
// Description: Detects creation of a file with an ".rdp" extension by an application that doesn't commonly create such files.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_file_path endswith ".rdp" and (action_process_image_path endswith "\\brave.exe" or action_process_image_path endswith "\\CCleaner Browser\\Application\\CCleanerBrowser.exe" or action_process_image_path endswith "\\chromium.exe" or action_process_image_path endswith "\\firefox.exe" or action_process_image_path endswith "\\Google\\Chrome\\Application\\chrome.exe" or action_process_image_path endswith "\\iexplore.exe" or action_process_image_path endswith "\\microsoftedge.exe" or action_process_image_path endswith "\\msedge.exe" or action_process_image_path endswith "\\Opera.exe" or action_process_image_path endswith "\\Vivaldi.exe" or action_process_image_path endswith "\\Whale.exe" or action_process_image_path endswith "\\olk.exe" or action_process_image_path endswith "\\Outlook.exe" or action_process_image_path endswith "\\RuntimeBroker.exe" or action_process_image_path endswith "\\Thunderbird.exe" or action_process_image_path endswith "\\Discord.exe" or action_process_image_path endswith "\\Keybase.exe" or action_process_image_path endswith "\\msteams.exe" or action_process_image_path endswith "\\Slack.exe" or action_process_image_path endswith "\\teams.exe"))
