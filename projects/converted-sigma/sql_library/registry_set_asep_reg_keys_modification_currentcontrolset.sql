-- Title: CurrentControlSet Autorun Keys Modification
-- ID: f674e36a-4b91-431e-8aef-f8a96c2aca35
-- Status: test
-- Level: medium
-- Author: Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
-- Date: 2019-10-25
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
-- Description: Detects modification of autostart extensibility point (ASEP) in registry.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((TargetObject ILIKE '%\\SYSTEM\\CurrentControlSet\\Control%') AND ((TargetObject ILIKE '%\\Terminal Server\\WinStations\\RDP-Tcp\\InitialProgram%' OR TargetObject ILIKE '%\\Terminal Server\\Wds\\rdpwd\\StartupPrograms%' OR TargetObject ILIKE '%\\SecurityProviders\\SecurityProviders%' OR TargetObject ILIKE '%\\SafeBoot\\AlternateShell%' OR TargetObject ILIKE '%\\Print\\Providers%' OR TargetObject ILIKE '%\\Print\\Monitors%' OR TargetObject ILIKE '%\\NetworkProvider\\Order%' OR TargetObject ILIKE '%\\Lsa\\Notification Packages%' OR TargetObject ILIKE '%\\Lsa\\Authentication Packages%' OR TargetObject ILIKE '%\\BootVerificationProgram\\ImagePath%'))) AND NOT (((Image = 'C:\\Windows\\System32\\spoolsv.exe' AND TargetObject ILIKE '%\\Print\\Monitors\\CutePDF Writer Monitor%' AND (Details = 'cpwmon64_v40.dll' OR Details = 'CutePDF Writer')) OR (Details = '(Empty)') OR (Image = 'C:\\Windows\\System32\\spoolsv.exe' AND TargetObject ILIKE '%Print\\Monitors\\Appmon\\Ports\\Microsoft.Office.OneNote_%' AND (User ILIKE '%AUTHORI%' OR User ILIKE '%AUTORI%')) OR (Image = 'C:\\Windows\\System32\\poqexec.exe' AND TargetObject ILIKE '%\\NetworkProvider\\Order\\ProviderOrder') OR (Image = 'C:\\Windows\\System32\\spoolsv.exe' AND TargetObject ILIKE '%\\Print\\Monitors\\MONVNC\\Driver' AND Details = 'VNCpm.dll'))))
