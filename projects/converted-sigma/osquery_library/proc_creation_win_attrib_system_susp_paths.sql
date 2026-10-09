-- Title: Set Suspicious Files as System Files Using Attrib.EXE
-- ID: efec536f-72e8-4656-8960-5e85d091345b
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-06-28
-- Tags: attack.stealth, attack.t1564.001
-- Description: Detects the usage of attrib with the "+s" option to set scripts or executables located in suspicious locations as system files to hide them from users and make them unable to be deleted with simple rights. The rule limits the search to specific extensions and directories to avoid FPs
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% +s%') AND ((CommandLine LIKE '%.bat%' OR CommandLine LIKE '%.dll%' OR CommandLine LIKE '%.exe%' OR CommandLine LIKE '%.hta%' OR CommandLine LIKE '%.ps1%' OR CommandLine LIKE '%.vbe%' OR CommandLine LIKE '%.vbs%')) AND ((Image="*\\attrib.exe") OR (OriginalFileName = 'ATTRIB.EXE')) AND ((CommandLine LIKE '% %%' OR CommandLine LIKE '%\\Users\\Public\\%' OR CommandLine LIKE '%\\AppData\\Local\\%' OR CommandLine LIKE '%\\ProgramData\\%' OR CommandLine LIKE '%\\Downloads\\%' OR CommandLine LIKE '%\\Windows\\Temp\\%'))) AND NOT (((CommandLine LIKE '%\\Windows\\TEMP\\%' AND CommandLine LIKE '%.exe%'))))
