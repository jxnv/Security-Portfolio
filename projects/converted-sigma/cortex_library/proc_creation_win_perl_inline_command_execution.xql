// Title: Perl Inline Command Execution
// ID: f426547a-e0f7-441a-b63e-854ac5bdf54d
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-02
// Tags: attack.execution, attack.t1059
// Description: Detects execution of perl using the "-e"/"-E" flags. This is could be used as a way to launch a reverse shell or execute live perl code.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " -e") and ((action_process_image_path endswith "\\perl.exe") or (action_process_image_name = "perl.exe")))
