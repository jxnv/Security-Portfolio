// Title: CurrentControlSet Autorun Keys Modification
// ID: f674e36a-4b91-431e-8aef-f8a96c2aca35
// Status: test
// Level: medium
// Author: Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
// Date: 2019-10-25
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
// Description: Detects modification of autostart extensibility point (ASEP) in registry.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "\\SYSTEM\\CurrentControlSet\\Control") and ((TargetObject contains "\\Terminal Server\\WinStations\\RDP-Tcp\\InitialProgram" or TargetObject contains "\\Terminal Server\\Wds\\rdpwd\\StartupPrograms" or TargetObject contains "\\SecurityProviders\\SecurityProviders" or TargetObject contains "\\SafeBoot\\AlternateShell" or TargetObject contains "\\Print\\Providers" or TargetObject contains "\\Print\\Monitors" or TargetObject contains "\\NetworkProvider\\Order" or TargetObject contains "\\Lsa\\Notification Packages" or TargetObject contains "\\Lsa\\Authentication Packages" or TargetObject contains "\\BootVerificationProgram\\ImagePath"))) and not (((action_process_image_path = "C:\\Windows\\System32\\spoolsv.exe" and TargetObject contains "\\Print\\Monitors\\CutePDF Writer Monitor" and (Details = "cpwmon64_v40.dll" or Details = "CutePDF Writer")) or (Details = "(Empty)") or (action_process_image_path = "C:\\Windows\\System32\\spoolsv.exe" and TargetObject contains "Print\\Monitors\\Appmon\\Ports\\Microsoft.Office.OneNote_" and (action_process_username contains "AUTHORI" or action_process_username contains "AUTORI")) or (action_process_image_path = "C:\\Windows\\System32\\poqexec.exe" and TargetObject endswith "\\NetworkProvider\\Order\\ProviderOrder") or (action_process_image_path = "C:\\Windows\\System32\\spoolsv.exe" and TargetObject endswith "\\Print\\Monitors\\MONVNC\\Driver" and Details = "VNCpm.dll"))))
