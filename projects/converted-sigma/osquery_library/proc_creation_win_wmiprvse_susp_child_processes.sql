-- Title: Suspicious WmiPrvSE Child Process
-- ID: 8a582fe2-0882-4b89-a82a-da6b2dc32937
-- Status: test
-- Level: high
-- Author: Vadim Khrykov (ThreatIntel), Cyb3rEng, Florian Roth (Nextron Systems)
-- Date: 2021-08-23
-- Tags: attack.execution, attack.stealth, attack.t1047, attack.t1204.002, attack.t1218.010
-- Description: Detects suspicious and uncommon child processes of WmiPrvSE
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((ParentImage="*\\wbem\\WmiPrvSE.exe") AND (((Image="*\\certutil.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe" OR Image="*\\msiexec.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\verclsid.exe" OR Image="*\\wscript.exe")) OR (Image="*\\cmd.exe" AND (CommandLine LIKE '%cscript%' OR CommandLine LIKE '%mshta%' OR CommandLine LIKE '%powershell%' OR CommandLine LIKE '%pwsh%' OR CommandLine LIKE '%regsvr32%' OR CommandLine LIKE '%rundll32%' OR CommandLine LIKE '%wscript%'))) AND NOT (((Image="*\\msiexec.exe" AND CommandLine LIKE '%/i %') OR (Image="*\\WerFault.exe") OR (Image="*\\WmiPrvSE.exe"))))
