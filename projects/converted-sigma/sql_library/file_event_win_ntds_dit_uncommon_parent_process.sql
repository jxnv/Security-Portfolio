-- Title: NTDS.DIT Creation By Uncommon Parent Process
-- ID: 4e7050dd-e548-483f-b7d6-527ab4fa784d
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-03-11
-- Tags: attack.credential-access, attack.t1003.003
-- Description: Detects creation of a file named "ntds.dit" (Active Directory Database) by an uncommon parent process or directory
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((TargetFilename ILIKE '%\\ntds.dit') AND (((ParentImage ILIKE '%\\cscript.exe' OR ParentImage ILIKE '%\\httpd.exe' OR ParentImage ILIKE '%\\nginx.exe' OR ParentImage ILIKE '%\\php-cgi.exe' OR ParentImage ILIKE '%\\powershell.exe' OR ParentImage ILIKE '%\\pwsh.exe' OR ParentImage ILIKE '%\\w3wp.exe' OR ParentImage ILIKE '%\\wscript.exe')) OR ((ParentImage ILIKE '%\\apache%' OR ParentImage ILIKE '%\\tomcat%' OR ParentImage ILIKE '%\\AppData\\%' OR ParentImage ILIKE '%\\Temp\\%' OR ParentImage ILIKE '%\\Public\\%' OR ParentImage ILIKE '%\\PerfLogs\\%'))))
