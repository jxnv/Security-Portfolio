// Title: WinSxS Executable File Creation By Non-System Process
// ID: 34746e8c-5fb8-415a-b135-0abc167e912a
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-11
// Tags: attack.execution
// Description: Detects the creation of binaries in the WinSxS folder by non-system processes
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path startswith "C:\\Windows\\WinSxS\\" and action_file_path endswith ".exe") and not (((action_process_image_path startswith "C:\\Windows\\Systems32\\" or action_process_image_path startswith "C:\\Windows\\SysWOW64\\" or action_process_image_path startswith "C:\\Windows\\WinSxS\\"))))
