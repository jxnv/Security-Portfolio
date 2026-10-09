// Title: ImagingDevices Unusual Parent/Child Processes
// ID: f11f2808-adb4-46c0-802a-8660db50fa99
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-27
// Tags: attack.execution, attack.stealth
// Description: Detects unusual parent or children of the ImagingDevices.exe (Windows Contacts) process as seen being used with Bumblebee activity
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\ImagingDevices.exe") or ((actor_process_image_path endswith "\\WmiPrvSE.exe" or actor_process_image_path endswith "\\svchost.exe" or actor_process_image_path endswith "\\dllhost.exe") and action_process_image_path endswith "\\ImagingDevices.exe"))
