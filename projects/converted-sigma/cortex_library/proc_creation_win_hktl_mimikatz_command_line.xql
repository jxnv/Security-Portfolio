// Title: HackTool - Mimikatz Execution
// ID: a642964e-bead-4bed-8910-1bb4d63e3b4d
// Status: test
// Level: high
// Author: Teymur Kheirkhabarov, oscd.community, David ANDRE (additional keywords), Tim Shelton
// Date: 2019-10-22
// Tags: attack.credential-access, attack.t1003.001, attack.t1003.002, attack.t1003.004, attack.t1003.005, attack.t1003.006
// Description: Detection well-known mimikatz command line arguments
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "::aadcookie" or action_process_image_command_line contains "::detours" or action_process_image_command_line contains "::memssp" or action_process_image_command_line contains "::mflt" or action_process_image_command_line contains "::ncroutemon" or action_process_image_command_line contains "::ngcsign" or action_process_image_command_line contains "::printnightmare" or action_process_image_command_line contains "::skeleton" or action_process_image_command_line contains "::preshutdown" or action_process_image_command_line contains "::mstsc" or action_process_image_command_line contains "::multirdp")) or ((action_process_image_command_line contains "rpc::" or action_process_image_command_line contains "token::" or action_process_image_command_line contains "crypto::" or action_process_image_command_line contains "dpapi::" or action_process_image_command_line contains "sekurlsa::" or action_process_image_command_line contains "kerberos::" or action_process_image_command_line contains "lsadump::" or action_process_image_command_line contains "privilege::" or action_process_image_command_line contains "process::" or action_process_image_command_line contains "vault::")) or ((action_process_image_command_line contains "DumpCreds" or action_process_image_command_line contains "mimikatz")))
