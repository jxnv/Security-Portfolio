-- Title: Rundll32 Execution With Uncommon DLL Extension
-- ID: c3a99af4-35a9-4668-879e-c09aeb4f2bdf
-- Status: test
-- Level: medium
-- Author: Tim Shelton, Florian Roth (Nextron Systems), Yassine Oukessou
-- Date: 2022-01-13
-- Tags: attack.stealth, attack.t1218.011
-- Description: Detects the execution of rundll32 with a command line that doesn't contain a common extension
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\rundll32.exe') OR (OriginalFileName = 'RUNDLL32.EXE')) AND NOT (((CommandLine = '') OR (((CommandLine ILIKE '%.cpl %' OR CommandLine ILIKE '%.cpl,%' OR CommandLine ILIKE '%.cpl\"%' OR CommandLine ILIKE '%.cpl'%' OR CommandLine ILIKE '%.dll %' OR CommandLine ILIKE '%.dll,%' OR CommandLine ILIKE '%.dll\"%' OR CommandLine ILIKE '%.dll'%' OR CommandLine ILIKE '%.inf %' OR CommandLine ILIKE '%.inf,%' OR CommandLine ILIKE '%.inf\"%' OR CommandLine ILIKE '%.inf'%')) OR ((CommandLine ILIKE '%.cpl' OR CommandLine ILIKE '%.dll' OR CommandLine ILIKE '%.inf'))) OR (CommandLine ILIKE '% -localserver %') OR (CommandLine IS NULL) OR (ParentImage ILIKE '%\\msiexec.exe' AND (CommandLine ILIKE '%:\\Windows\\Installer\\%' AND CommandLine ILIKE '%.tmp%' AND CommandLine ILIKE '%zzzzInvokeManagedCustomActionOutOfProc%')))) AND NOT (((ParentCommandLine ILIKE '%:\\Users\\%' AND ParentCommandLine ILIKE '%\\AppData\\Local\\Microsoft\\EdgeUpdate\\Install\\{%' AND ParentCommandLine ILIKE '%\\EDGEMITMP_%' AND ParentCommandLine ILIKE '%.tmp\\setup.exe%' AND ParentCommandLine ILIKE '%--install-archive=%' AND ParentCommandLine ILIKE '%--previous-version=%' AND ParentCommandLine ILIKE '%--msedgewebview --verbose-logging --do-not-launch-msedge --user-level%'))))
