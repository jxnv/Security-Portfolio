// Title: Remote Access Tool - MeshAgent Command Execution via MeshCentral
// ID: 74a2b202-73e0-4693-9a3a-9d36146d0775
// Status: test
// Level: medium
// Author: @Kostastsale
// Date: 2024-09-22
// Tags: attack.command-and-control, attack.t1219.002
// Description: Detects the use of MeshAgent to execute commands on the target host, particularly when threat actors might abuse it to execute commands directly.
// MeshAgent can execute commands on the target host by leveraging win-console to obscure their activities and win-dispatcher to run malicious code through IPC with child processes.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\meshagent.exe" and (action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe"))
