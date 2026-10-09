-- Title: Potential PowerShell Obfuscation Via Reversed Commands
-- ID: b6b49cd1-34d6-4ead-b1bf-176e9edba9a4
-- Status: test
-- Level: high
-- Author: Teymur Kheirkhabarov (idea), Vasiliy Burov (rule), oscd.community, Tim Shelton
-- Date: 2020-10-11
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects the presence of reversed PowerShell commands in the CommandLine. This is often used as a method of obfuscation by attackers
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%hctac%' OR CommandLine LIKE '%kaerb%' OR CommandLine LIKE '%dnammoc%' OR CommandLine LIKE '%ekovn%' OR CommandLine LIKE '%eliFd%' OR CommandLine LIKE '%rahc%' OR CommandLine LIKE '%etirw%' OR CommandLine LIKE '%golon%' OR CommandLine LIKE '%tninon%' OR CommandLine LIKE '%eddih%' OR CommandLine LIKE '%tpircS%' OR CommandLine LIKE '%ssecorp%' OR CommandLine LIKE '%llehsrewop%' OR CommandLine LIKE '%esnopser%' OR CommandLine LIKE '%daolnwod%' OR CommandLine LIKE '%tneilCbeW%' OR CommandLine LIKE '%tneilc%' OR CommandLine LIKE '%ptth%' OR CommandLine LIKE '%elifotevas%' OR CommandLine LIKE '%46esab%' OR CommandLine LIKE '%htaPpmeTteG%' OR CommandLine LIKE '%tcejbO%' OR CommandLine LIKE '%maerts%' OR CommandLine LIKE '%hcaerof%' OR CommandLine LIKE '%retupmoc%')) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll')))) AND NOT (((CommandLine LIKE '% -EncodedCommand %' OR CommandLine LIKE '% -enc %'))))
