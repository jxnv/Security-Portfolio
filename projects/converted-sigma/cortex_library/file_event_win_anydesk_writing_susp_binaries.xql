// Title: Suspicious Binary Writes Via AnyDesk
// ID: 2d367498-5112-4ae5-a06a-96e7bc33a211
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-28
// Tags: attack.command-and-control, attack.t1219.002
// Description: Detects AnyDesk writing binary files to disk other than "gcapi.dll".
// According to RedCanary research it is highly abnormal for AnyDesk to write executable files to disk besides gcapi.dll,
// which is a legitimate DLL that is part of the Google Chrome web browser used to interact with the Google Cloud API. (See reference section for more details)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\AnyDesk.exe" or action_process_image_path endswith "\\AnyDeskMSI.exe") and (action_file_path endswith ".dll" or action_file_path endswith ".exe")) and not ((action_file_path endswith "\\gcapi.dll")))
