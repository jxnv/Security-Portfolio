// Title: Certificate Exported Via Certutil.EXE
// ID: 3ffd6f51-e6c1-47b7-94b4-c1e61d4117c5
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-15
// Tags: attack.stealth, attack.t1027
// Description: Detects the execution of the certutil with the "exportPFX" flag which allows the utility to export certificates.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-exportPFX " or action_process_image_command_line contains "/exportPFX ")) and ((action_process_image_path endswith "\\certutil.exe") or (action_process_image_name = "CertUtil.exe")))
