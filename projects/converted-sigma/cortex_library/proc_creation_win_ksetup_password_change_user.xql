// Title: Logged-On User Password Change Via Ksetup.EXE
// ID: c9783e20-4793-4164-ba96-d9ee483992c4
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-06
// Tags: attack.execution
// Description: Detects password change for the logged-on user's via "ksetup.exe"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " /ChangePassword ") and ((action_process_image_path endswith "\\ksetup.exe") or (action_process_image_name = "ksetup.exe")))
