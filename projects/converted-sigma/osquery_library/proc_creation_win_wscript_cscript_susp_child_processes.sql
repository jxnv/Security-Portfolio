-- Title: Cscript/Wscript Potentially Suspicious Child Process
-- ID: b6676963-0353-4f88-90f5-36c20d443c6a
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), Alejandro Houspanossian ('@lekz86')
-- Date: 2023-05-15
-- Tags: attack.execution
-- Description: Detects potentially suspicious child processes of Wscript/Cscript. These include processes such as rundll32 with uncommon exports or PowerShell spawning rundll32 or regsvr32.
-- Malware such as Pikabot and Qakbot were seen using similar techniques as well as many others.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((ParentImage="*\\wscript.exe" OR ParentImage="*\\cscript.exe")) AND ((Image="*\\rundll32.exe") OR (((Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) AND (((CommandLine LIKE '%mshta%' AND CommandLine LIKE '%http%')) OR ((CommandLine LIKE '%rundll32%' OR CommandLine LIKE '%regsvr32%' OR CommandLine LIKE '%msiexec%'))))) AND NOT ((Image="*\\rundll32.exe" AND (CommandLine LIKE '%UpdatePerUserSystemParameters%' OR CommandLine LIKE '%PrintUIEntry%' OR CommandLine LIKE '%ClearMyTracksByProcess%'))))
