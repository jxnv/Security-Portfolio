-- Title: Potentially Suspicious Execution From Parent Process In Public Folder
-- ID: 69bd9b97-2be2-41b6-9816-fb08757a4d1a
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-02-25
-- Tags: attack.execution, attack.stealth, attack.t1564, attack.t1059
-- Description: Detects a potentially suspicious execution of a parent process located in the "\Users\Public" folder executing a child process containing references to shell or scripting binaries and commandlines.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((Image ILIKE '%\\bitsadmin.exe' OR Image ILIKE '%\\certutil.exe' OR Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\wscript.exe')) OR ((CommandLine ILIKE '%bitsadmin%' OR CommandLine ILIKE '%certutil%' OR CommandLine ILIKE '%cscript%' OR CommandLine ILIKE '%mshta%' OR CommandLine ILIKE '%powershell%' OR CommandLine ILIKE '%regsvr32%' OR CommandLine ILIKE '%rundll32%' OR CommandLine ILIKE '%wscript%'))) AND (ParentImage ILIKE '%:\\Users\\Public\\%'))
