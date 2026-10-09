// Title: SyncAppvPublishingServer Execute Arbitrary PowerShell Code
// ID: fbd7c32d-db2a-4418-b92c-566eb8911133
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-07-12
// Tags: attack.stealth, attack.t1218
// Description: Executes arbitrary PowerShell code using SyncAppvPublishingServer.exe.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "\"n; ") and ((action_process_image_path endswith "\\SyncAppvPublishingServer.exe") or (action_process_image_name = "syncappvpublishingserver.exe")))
