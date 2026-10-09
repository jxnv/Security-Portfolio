// Title: DD File Overwrite
// ID: 2953194b-e33c-4859-b9e8-05948c167447
// Status: test
// Level: low
// Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
// Date: 2021-10-15
// Tags: attack.impact, attack.t1485
// Description: Detects potential overwriting and deletion of a file using DD.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path = "/bin/dd" or action_process_image_path = "/usr/bin/dd")) and (action_process_image_command_line contains "of=") and ((action_process_image_command_line contains "if=/dev/zero" or action_process_image_command_line contains "if=/dev/null")))
