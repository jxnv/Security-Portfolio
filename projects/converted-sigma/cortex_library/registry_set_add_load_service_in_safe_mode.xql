// Title: Registry Persistence via Service in Safe Mode
// ID: 1547e27c-3974-43e2-a7d7-7f484fb928ec
// Status: test
// Level: high
// Author: frack113
// Date: 2022-04-04
// Tags: attack.stealth, attack.t1564.001
// Description: Detects the modification of the registry to allow a driver or service to persist in Safe Mode.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "\\Control\\SafeBoot\\Minimal\\" or TargetObject contains "\\Control\\SafeBoot\\Network\\") and TargetObject endswith "\\(Default)" and Details = "Service") and not (((action_process_image_path = "C:\\Hexnode\\Hexnode Agent\\Current\\HexnodeAgent.exe" and (TargetObject endswith "\\Control\\SafeBoot\\Minimal\\Hexnode Updater\\(Default)" or TargetObject endswith "\\Control\\SafeBoot\\Network\\Hexnode Updater\\(Default)" or TargetObject endswith "\\Control\\SafeBoot\\Minimal\\Hexnode Agent\\(Default)" or TargetObject endswith "\\Control\\SafeBoot\\Network\\Hexnode Agent\\(Default)") and Details = "Service") or (action_process_image_path endswith "\\MBAMInstallerService.exe" and TargetObject endswith "\\MBAMService\\(Default)" and Details = "Service") or (action_process_image_path = "C:\\WINDOWS\\system32\\msiexec.exe" and (TargetObject endswith "\\Control\\SafeBoot\\Minimal\\SAVService\\(Default)" or TargetObject endswith "\\Control\\SafeBoot\\Network\\SAVService\\(Default)")))))
