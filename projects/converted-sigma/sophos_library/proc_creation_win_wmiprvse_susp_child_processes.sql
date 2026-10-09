-- Title: Suspicious WmiPrvSE Child Process
-- ID: 8a582fe2-0882-4b89-a82a-da6b2dc32937
-- Status: test
-- Level: high
-- Author: Vadim Khrykov (ThreatIntel), Cyb3rEng, Florian Roth (Nextron Systems)
-- Date: 2021-08-23
-- Tags: attack.execution, attack.stealth, attack.t1047, attack.t1204.002, attack.t1218.010
-- Description: Detects suspicious and uncommon child processes of WmiPrvSE
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ParentImage ILIKE '%\\wbem\\WmiPrvSE.exe') AND (((Image ILIKE '%\\certutil.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\msiexec.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\verclsid.exe' OR Image ILIKE '%\\wscript.exe')) OR (Image ILIKE '%\\cmd.exe' AND (CommandLine ILIKE '%cscript%' OR CommandLine ILIKE '%mshta%' OR CommandLine ILIKE '%powershell%' OR CommandLine ILIKE '%pwsh%' OR CommandLine ILIKE '%regsvr32%' OR CommandLine ILIKE '%rundll32%' OR CommandLine ILIKE '%wscript%'))) AND NOT (((Image ILIKE '%\\msiexec.exe' AND CommandLine ILIKE '%/i %') OR (Image ILIKE '%\\WerFault.exe') OR (Image ILIKE '%\\WmiPrvSE.exe'))))
