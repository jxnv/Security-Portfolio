-- Title: Shell32 DLL Execution in Suspicious Directory
-- ID: 32b96012-7892-429e-b26c-ac2bf46066ff
-- Status: test
-- Level: high
-- Author: Christian Burkard (Nextron Systems)
-- Date: 2021-11-24
-- Tags: attack.execution, attack.stealth, attack.t1218.011
-- Description: Detects shell32.dll executing a DLL in a suspicious directory
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%shell32.dll%' AND CommandLine LIKE '%Control_RunDLL%') AND (CommandLine LIKE '%%AppData%%' OR CommandLine LIKE '%%LocalAppData%%' OR CommandLine LIKE '%%Temp%%' OR CommandLine LIKE '%%tmp%%' OR CommandLine LIKE '%\\AppData\\%' OR CommandLine LIKE '%\\Temp\\%' OR CommandLine LIKE '%\\Users\\Public\\%')) AND ((Image="*\\rundll32.exe") OR (OriginalFileName = 'RUNDLL32.EXE')))
