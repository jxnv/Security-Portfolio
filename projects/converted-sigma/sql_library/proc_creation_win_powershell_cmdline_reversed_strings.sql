-- Title: Potential PowerShell Obfuscation Via Reversed Commands
-- ID: b6b49cd1-34d6-4ead-b1bf-176e9edba9a4
-- Status: test
-- Level: high
-- Author: Teymur Kheirkhabarov (idea), Vasiliy Burov (rule), oscd.community, Tim Shelton
-- Date: 2020-10-11
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects the presence of reversed PowerShell commands in the CommandLine. This is often used as a method of obfuscation by attackers
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((CommandLine ILIKE '%hctac%' OR CommandLine ILIKE '%kaerb%' OR CommandLine ILIKE '%dnammoc%' OR CommandLine ILIKE '%ekovn%' OR CommandLine ILIKE '%eliFd%' OR CommandLine ILIKE '%rahc%' OR CommandLine ILIKE '%etirw%' OR CommandLine ILIKE '%golon%' OR CommandLine ILIKE '%tninon%' OR CommandLine ILIKE '%eddih%' OR CommandLine ILIKE '%tpircS%' OR CommandLine ILIKE '%ssecorp%' OR CommandLine ILIKE '%llehsrewop%' OR CommandLine ILIKE '%esnopser%' OR CommandLine ILIKE '%daolnwod%' OR CommandLine ILIKE '%tneilCbeW%' OR CommandLine ILIKE '%tneilc%' OR CommandLine ILIKE '%ptth%' OR CommandLine ILIKE '%elifotevas%' OR CommandLine ILIKE '%46esab%' OR CommandLine ILIKE '%htaPpmeTteG%' OR CommandLine ILIKE '%tcejbO%' OR CommandLine ILIKE '%maerts%' OR CommandLine ILIKE '%hcaerof%' OR CommandLine ILIKE '%retupmoc%')) AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll')))) AND NOT (((CommandLine ILIKE '% -EncodedCommand %' OR CommandLine ILIKE '% -enc %'))))
