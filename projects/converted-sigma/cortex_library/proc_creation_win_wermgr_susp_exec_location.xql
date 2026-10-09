// Title: Suspicious Execution Location Of Wermgr.EXE
// ID: 5394fcc7-aeb2-43b5-9a09-cac9fc5edcd5
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-10-14
// Tags: attack.execution
// Description: Detects suspicious Windows Error Reporting manager (wermgr.exe) execution location.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\wermgr.exe") and not (((action_process_image_path startswith "C:\\Windows\\System32\\" or action_process_image_path startswith "C:\\Windows\\SysWOW64\\" or action_process_image_path startswith "C:\\Windows\\WinSxS\\"))))
