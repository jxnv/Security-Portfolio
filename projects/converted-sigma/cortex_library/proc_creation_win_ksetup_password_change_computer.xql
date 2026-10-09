// Title: Computer Password Change Via Ksetup.EXE
// ID: de16d92c-c446-4d53-8938-10aeef41c8b6
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-06
// Tags: attack.execution
// Description: Detects password change for the computer's domain account or host principal via "ksetup.exe"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " /setcomputerpassword ") and ((action_process_image_path endswith "\\ksetup.exe") or (action_process_image_name = "ksetup.exe")))
