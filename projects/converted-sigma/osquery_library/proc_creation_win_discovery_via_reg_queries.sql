-- Title: System Information Discovery via Registry Queries
-- ID: 0022869c-49f7-4ff2-ba03-85ac42ddac58
-- Status: experimental
-- Level: low
-- Author: lazarg
-- Date: 2025-06-12
-- Tags: attack.discovery, attack.t1082
-- Description: Detects attempts to query system information directly from the Windows Registry.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((Image="*\\powershell.exe" OR Image="*\\pwsh.exe") AND (CommandLine LIKE '%Get-ItemPropertyValue%' OR CommandLine LIKE '%gpv%')) OR (Image="*\\reg.exe" AND CommandLine LIKE '%query%' AND (CommandLine LIKE '%-v%' OR CommandLine LIKE '%/v%'))) AND ((CommandLine LIKE '%\\SOFTWARE\\Microsoft\\Windows Defender%' OR CommandLine LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion%' OR CommandLine LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall%' OR CommandLine LIKE '%\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation%' OR CommandLine LIKE '%\\SYSTEM\\CurrentControlSet\\Services%')))
