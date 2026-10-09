-- Title: Rundll32 Execution With Uncommon DLL Extension
-- ID: c3a99af4-35a9-4668-879e-c09aeb4f2bdf
-- Status: test
-- Level: medium
-- Author: Tim Shelton, Florian Roth (Nextron Systems), Yassine Oukessou
-- Date: 2022-01-13
-- Tags: attack.stealth, attack.t1218.011
-- Description: Detects the execution of rundll32 with a command line that doesn't contain a common extension
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\rundll32.exe") OR (OriginalFileName = 'RUNDLL32.EXE')) AND NOT (((CommandLine = '') OR (((CommandLine LIKE '%.cpl %' OR CommandLine LIKE '%.cpl,%' OR CommandLine LIKE '%.cpl\"%' OR CommandLine LIKE '%.cpl'%' OR CommandLine LIKE '%.dll %' OR CommandLine LIKE '%.dll,%' OR CommandLine LIKE '%.dll\"%' OR CommandLine LIKE '%.dll'%' OR CommandLine LIKE '%.inf %' OR CommandLine LIKE '%.inf,%' OR CommandLine LIKE '%.inf\"%' OR CommandLine LIKE '%.inf'%')) OR ((CommandLine="*.cpl" OR CommandLine="*.dll" OR CommandLine="*.inf"))) OR (CommandLine LIKE '% -localserver %') OR (NOT CommandLine=*) OR (ParentImage="*\\msiexec.exe" AND (CommandLine LIKE '%:\\Windows\\Installer\\%' AND CommandLine LIKE '%.tmp%' AND CommandLine LIKE '%zzzzInvokeManagedCustomActionOutOfProc%')))) AND NOT (((ParentCommandLine LIKE '%:\\Users\\%' AND ParentCommandLine LIKE '%\\AppData\\Local\\Microsoft\\EdgeUpdate\\Install\\{%' AND ParentCommandLine LIKE '%\\EDGEMITMP_%' AND ParentCommandLine LIKE '%.tmp\\setup.exe%' AND ParentCommandLine LIKE '%--install-archive=%' AND ParentCommandLine LIKE '%--previous-version=%' AND ParentCommandLine LIKE '%--msedgewebview --verbose-logging --do-not-launch-msedge --user-level%'))))
