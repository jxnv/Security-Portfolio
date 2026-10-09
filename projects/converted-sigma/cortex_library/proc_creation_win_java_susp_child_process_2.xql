// Title: Shell Process Spawned by Java.EXE
// ID: dff1e1cc-d3fd-47c8-bfc2-aeb878a754c0
// Status: test
// Level: medium
// Author: Andreas Hunkeler (@Karneades), Nasreddine Bencherchali
// Date: 2021-12-17
// Tags: attack.initial-access, attack.persistence, attack.privilege-escalation
// Description: Detects shell spawned from Java host process, which could be a sign of exploitation (e.g. log4j exploitation)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\java.exe" and (action_process_image_path endswith "\\bash.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) and not ((actor_process_image_path contains "build" and action_process_image_command_line contains "build")))
