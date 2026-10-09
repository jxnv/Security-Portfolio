-- Title: Suspicious Child Process Of Wermgr.EXE
-- ID: 396f6630-f3ac-44e3-bfc8-1b161bc00c4e
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-10-14
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1055, attack.t1036
-- Description: Detects suspicious Windows Error Reporting manager (wermgr.exe) child process
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ParentImage ILIKE '%\\wermgr.exe' AND (Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\ipconfig.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\net.exe' OR Image ILIKE '%\\net1.exe' OR Image ILIKE '%\\netstat.exe' OR Image ILIKE '%\\nslookup.exe' OR Image ILIKE '%\\powershell_ise.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\systeminfo.exe' OR Image ILIKE '%\\whoami.exe' OR Image ILIKE '%\\wscript.exe')) AND NOT ((Image ILIKE '%\\rundll32.exe' AND (CommandLine ILIKE '%C:\\Windows\\system32\\WerConCpl.dll%' AND CommandLine ILIKE '%LaunchErcApp %') AND (CommandLine ILIKE '%-queuereporting%' OR CommandLine ILIKE '%-responsepester%'))))
