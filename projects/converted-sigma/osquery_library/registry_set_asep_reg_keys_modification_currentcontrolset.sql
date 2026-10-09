-- Title: CurrentControlSet Autorun Keys Modification
-- ID: f674e36a-4b91-431e-8aef-f8a96c2aca35
-- Status: test
-- Level: medium
-- Author: Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
-- Date: 2019-10-25
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
-- Description: Detects modification of autostart extensibility point (ASEP) in registry.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((TargetObject LIKE '%\\SYSTEM\\CurrentControlSet\\Control%') AND ((TargetObject LIKE '%\\Terminal Server\\WinStations\\RDP-Tcp\\InitialProgram%' OR TargetObject LIKE '%\\Terminal Server\\Wds\\rdpwd\\StartupPrograms%' OR TargetObject LIKE '%\\SecurityProviders\\SecurityProviders%' OR TargetObject LIKE '%\\SafeBoot\\AlternateShell%' OR TargetObject LIKE '%\\Print\\Providers%' OR TargetObject LIKE '%\\Print\\Monitors%' OR TargetObject LIKE '%\\NetworkProvider\\Order%' OR TargetObject LIKE '%\\Lsa\\Notification Packages%' OR TargetObject LIKE '%\\Lsa\\Authentication Packages%' OR TargetObject LIKE '%\\BootVerificationProgram\\ImagePath%'))) AND NOT (((Image = 'C:\\Windows\\System32\\spoolsv.exe' AND TargetObject LIKE '%\\Print\\Monitors\\CutePDF Writer Monitor%' AND (Details = 'cpwmon64_v40.dll' OR Details = 'CutePDF Writer')) OR (Details = '(Empty)') OR (Image = 'C:\\Windows\\System32\\spoolsv.exe' AND TargetObject LIKE '%Print\\Monitors\\Appmon\\Ports\\Microsoft.Office.OneNote_%' AND (User LIKE '%AUTHORI%' OR User LIKE '%AUTORI%')) OR (Image = 'C:\\Windows\\System32\\poqexec.exe' AND TargetObject="*\\NetworkProvider\\Order\\ProviderOrder") OR (Image = 'C:\\Windows\\System32\\spoolsv.exe' AND TargetObject="*\\Print\\Monitors\\MONVNC\\Driver" AND Details = 'VNCpm.dll'))))
