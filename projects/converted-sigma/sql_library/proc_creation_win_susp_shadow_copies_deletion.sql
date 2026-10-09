-- Title: Shadow Copies Deletion Using Operating Systems Utilities
-- ID: c947b146-0abc-4c87-9c64-b17e9d7274a2
-- Status: stable
-- Level: high
-- Author: Florian Roth (Nextron Systems), Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community, Andreas Hunkeler (@Karneades)
-- Date: 2019-10-22
-- Tags: attack.impact, attack.stealth, attack.t1070, attack.t1490
-- Description: Shadow Copies deletion using operating systems utilities
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((CommandLine ILIKE '%shadow%' AND CommandLine ILIKE '%delete%')) AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\wmic.exe' OR Image ILIKE '%\\vssadmin.exe' OR Image ILIKE '%\\diskshadow.exe')) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll' OR OriginalFileName = 'wmic.exe' OR OriginalFileName = 'VSSADMIN.EXE' OR OriginalFileName = 'diskshadow.exe')))) OR (((CommandLine ILIKE '%delete%' AND CommandLine ILIKE '%catalog%' AND CommandLine ILIKE '%quiet%')) AND ((Image ILIKE '%\\wbadmin.exe') OR (OriginalFileName = 'WBADMIN.EXE'))) OR (((CommandLine ILIKE '%resize%' AND CommandLine ILIKE '%shadowstorage%') AND (CommandLine ILIKE '%unbounded%' OR CommandLine ILIKE '%/MaxSize=%')) AND ((Image ILIKE '%\\vssadmin.exe') OR (OriginalFileName = 'VSSADMIN.EXE'))))
