// Title: Rebuild Performance Counter Values Via Lodctr.EXE
// ID: cc9d3712-6310-4320-b2df-7cb408274d53
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-06-15
// Tags: attack.execution
// Description: Detects the execution of "lodctr.exe" to rebuild the performance counter registry values. This can be abused by attackers by providing a malicious config file to overwrite performance counter configuration to confuse and evade monitoring and security solutions.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " -r") and (action_process_image_path endswith "\\lodctr.exe" and action_process_image_name = "LODCTR.EXE"))
