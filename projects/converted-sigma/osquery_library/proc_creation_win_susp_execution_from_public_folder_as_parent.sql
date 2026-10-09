-- Title: Potentially Suspicious Execution From Parent Process In Public Folder
-- ID: 69bd9b97-2be2-41b6-9816-fb08757a4d1a
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-02-25
-- Tags: attack.execution, attack.stealth, attack.t1564, attack.t1059
-- Description: Detects a potentially suspicious execution of a parent process located in the "\Users\Public" folder executing a child process containing references to shell or scripting binaries and commandlines.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((Image="*\\bitsadmin.exe" OR Image="*\\certutil.exe" OR Image="*\\cmd.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\wscript.exe")) OR ((CommandLine LIKE '%bitsadmin%' OR CommandLine LIKE '%certutil%' OR CommandLine LIKE '%cscript%' OR CommandLine LIKE '%mshta%' OR CommandLine LIKE '%powershell%' OR CommandLine LIKE '%regsvr32%' OR CommandLine LIKE '%rundll32%' OR CommandLine LIKE '%wscript%'))) AND (ParentImage LIKE '%:\\Users\\Public\\%'))
