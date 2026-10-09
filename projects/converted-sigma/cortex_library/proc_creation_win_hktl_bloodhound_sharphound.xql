// Title: HackTool - Bloodhound/Sharphound Execution
// ID: f376c8a7-a2d0-4ddc-aa0c-16c17236d962
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2019-12-20
// Tags: attack.discovery, attack.t1087.001, attack.t1087.002, attack.t1482, attack.t1069.001, attack.t1069.002, attack.execution, attack.t1059.001
// Description: Detects command line parameters used by Bloodhound and Sharphound hack tools
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -CollectionMethod All " or action_process_image_command_line contains " --CollectionMethods Session " or action_process_image_command_line contains " --Loop --Loopduration " or action_process_image_command_line contains " --PortScanTimeout " or action_process_image_command_line contains ".exe -c All -d " or action_process_image_command_line contains "Invoke-Bloodhound" or action_process_image_command_line contains "Get-BloodHoundData")) or ((action_process_image_command_line contains " -JsonFolder " and action_process_image_command_line contains " -ZipFileName ")) or ((action_process_image_command_line contains " DCOnly " and action_process_image_command_line contains " --NoSaveCache ")) or ((Product contains "SharpHound") or (Description contains "SharpHound") or ((Company contains "SpecterOps" or Company contains "evil corp")) or ((action_process_image_path contains "\\Bloodhound.exe" or action_process_image_path contains "\\SharpHound.exe"))))
