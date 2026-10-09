-- Title: Shell32 DLL Execution in Suspicious Directory
-- ID: 32b96012-7892-429e-b26c-ac2bf46066ff
-- Status: test
-- Level: high
-- Author: Christian Burkard (Nextron Systems)
-- Date: 2021-11-24
-- Tags: attack.execution, attack.stealth, attack.t1218.011
-- Description: Detects shell32.dll executing a DLL in a suspicious directory
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%shell32.dll%' AND CommandLine ILIKE '%Control_RunDLL%') AND (CommandLine ILIKE '%%AppData%%' OR CommandLine ILIKE '%%LocalAppData%%' OR CommandLine ILIKE '%%Temp%%' OR CommandLine ILIKE '%%tmp%%' OR CommandLine ILIKE '%\\AppData\\%' OR CommandLine ILIKE '%\\Temp\\%' OR CommandLine ILIKE '%\\Users\\Public\\%')) AND ((Image ILIKE '%\\rundll32.exe') OR (OriginalFileName = 'RUNDLL32.EXE')))
