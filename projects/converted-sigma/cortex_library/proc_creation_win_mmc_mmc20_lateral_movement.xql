// Title: MMC20 Lateral Movement
// ID: f1f3bf22-deb2-418d-8cce-e1a45e46a5bd
// Status: test
// Level: high
// Author: @2xxeformyshirt (Security Risk Advisors) - rule; Teymur Kheirkhabarov (idea)
// Date: 2020-03-04
// Tags: attack.execution, attack.lateral-movement, attack.t1021.003
// Description: Detects MMC20.Application Lateral Movement; specifically looks for the spawning of the parent MMC.exe with a command line of "-Embedding" as a child of svchost.exe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\svchost.exe" and action_process_image_path endswith "\\mmc.exe" and action_process_image_command_line contains "-Embedding")
