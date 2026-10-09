-- Title: Shadow Copies Deletion Using Operating Systems Utilities
-- ID: c947b146-0abc-4c87-9c64-b17e9d7274a2
-- Status: stable
-- Level: high
-- Author: Florian Roth (Nextron Systems), Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community, Andreas Hunkeler (@Karneades)
-- Date: 2019-10-22
-- Tags: attack.impact, attack.stealth, attack.t1070, attack.t1490
-- Description: Shadow Copies deletion using operating systems utilities
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%shadow%' AND CommandLine LIKE '%delete%')) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\wmic.exe" OR Image="*\\vssadmin.exe" OR Image="*\\diskshadow.exe")) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll' OR OriginalFileName = 'wmic.exe' OR OriginalFileName = 'VSSADMIN.EXE' OR OriginalFileName = 'diskshadow.exe')))) OR (((CommandLine LIKE '%delete%' AND CommandLine LIKE '%catalog%' AND CommandLine LIKE '%quiet%')) AND ((Image="*\\wbadmin.exe") OR (OriginalFileName = 'WBADMIN.EXE'))) OR (((CommandLine LIKE '%resize%' AND CommandLine LIKE '%shadowstorage%') AND (CommandLine LIKE '%unbounded%' OR CommandLine LIKE '%/MaxSize=%')) AND ((Image="*\\vssadmin.exe") OR (OriginalFileName = 'VSSADMIN.EXE'))))
