-- Title: Potential Defense Evasion Via Binary Rename
-- ID: 36480ae1-a1cb-4eaa-a0d6-29801d7e9142
-- Status: test
-- Level: medium
-- Author: Matthew Green @mgreen27, Ecco, James Pemberton @4A616D6573, oscd.community, Andreas Hunkeler (@Karneades)
-- Date: 2019-06-15
-- Tags: attack.stealth, attack.t1036.003
-- Description: Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((OriginalFileName = 'Cmd.Exe' OR OriginalFileName = 'CONHOST.EXE' OR OriginalFileName = '7z.exe' OR OriginalFileName = '7za.exe' OR OriginalFileName = '7zr.exe' OR OriginalFileName = 'WinRAR.exe' OR OriginalFileName = 'wevtutil.exe' OR OriginalFileName = 'net.exe' OR OriginalFileName = 'net1.exe' OR OriginalFileName = 'netsh.exe' OR OriginalFileName = 'InstallUtil.exe')) AND NOT (((Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\conhost.exe' OR Image ILIKE '%\\7z.exe' OR Image ILIKE '%\\7za.exe' OR Image ILIKE '%\\7zr.exe' OR Image ILIKE '%\\WinRAR.exe' OR Image ILIKE '%\\wevtutil.exe' OR Image ILIKE '%\\net.exe' OR Image ILIKE '%\\net1.exe' OR Image ILIKE '%\\netsh.exe' OR Image ILIKE '%\\InstallUtil.exe'))))
