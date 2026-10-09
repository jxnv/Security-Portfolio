// Title: PsExec Tool Execution From Suspicious Locations - PipeName
// ID: 41504465-5e3a-4a5b-a5b4-2a0baadd4463
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-04
// Tags: attack.execution, attack.t1569.002, attack.s0029
// Description: Detects PsExec default pipe creation where the image executed is located in a suspicious location. Which could indicate that the tool is being used in an attack
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (PipeName = "\\PSEXESVC" and (action_process_image_path contains ":\\Users\\Public\\" or action_process_image_path contains ":\\Windows\\Temp\\" or action_process_image_path contains "\\AppData\\Local\\Temp\\" or action_process_image_path contains "\\Desktop\\" or action_process_image_path contains "\\Downloads\\"))
