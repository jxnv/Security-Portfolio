// Title: Uncommon Svchost Parent Process
// ID: 01d2e2a1-5f09-44f7-9fc1-24faa7479b6d
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2017-08-15
// Tags: attack.stealth, attack.t1036.005
// Description: Detects an uncommon svchost parent process
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\svchost.exe") and not ((((actor_process_image_path endswith "\\Mrt.exe" or actor_process_image_path endswith "\\MsMpEng.exe" or actor_process_image_path endswith "\\ngen.exe" or actor_process_image_path endswith "\\rpcnet.exe" or actor_process_image_path endswith "\\services.exe" or actor_process_image_path endswith "\\TiWorker.exe")) or ((actor_process_image_path = "-" or actor_process_image_path = "")) or (actor_process_image_path = null))))
