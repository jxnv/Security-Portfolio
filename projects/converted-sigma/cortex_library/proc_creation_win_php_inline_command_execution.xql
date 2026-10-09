// Title: Php Inline Command Execution
// ID: d81871ef-5738-47ab-9797-7a9c90cd4bfb
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-02
// Tags: attack.execution, attack.t1059
// Description: Detects execution of php using the "-r" flag. This is could be used as a way to launch a reverse shell or execute live php code.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " -r") and ((action_process_image_path endswith "\\php.exe") or (action_process_image_name = "php.exe")))
