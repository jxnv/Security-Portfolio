// Title: PUA - Seatbelt Execution
// ID: 38646daa-e78f-4ace-9de0-55547b2d30da
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-18
// Tags: attack.discovery, attack.t1526, attack.t1087, attack.t1083
// Description: Detects the execution of the PUA/Recon tool Seatbelt via PE information of command line parameters
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\Seatbelt.exe") or (action_process_image_name = "Seatbelt.exe") or (Description = "Seatbelt") or ((action_process_image_command_line contains " DpapiMasterKeys" or action_process_image_command_line contains " InterestingProcesses" or action_process_image_command_line contains " InterestingFiles" or action_process_image_command_line contains " CertificateThumbprints" or action_process_image_command_line contains " ChromiumBookmarks" or action_process_image_command_line contains " ChromiumHistory" or action_process_image_command_line contains " ChromiumPresence" or action_process_image_command_line contains " CloudCredentials" or action_process_image_command_line contains " CredEnum" or action_process_image_command_line contains " CredGuard" or action_process_image_command_line contains " FirefoxHistory" or action_process_image_command_line contains " ProcessCreationEvents"))) or (((action_process_image_command_line contains " -group=misc" or action_process_image_command_line contains " -group=remote" or action_process_image_command_line contains " -group=chromium" or action_process_image_command_line contains " -group=slack" or action_process_image_command_line contains " -group=system" or action_process_image_command_line contains " -group=user" or action_process_image_command_line contains " -group=all")) and (action_process_image_command_line contains " -outputfile=")))
