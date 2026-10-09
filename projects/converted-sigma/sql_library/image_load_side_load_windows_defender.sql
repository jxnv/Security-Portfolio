-- Title: Potential Mpclient.DLL Sideloading
-- ID: 418dc89a-9808-4b87-b1d7-e5ae0cb6effc
-- Status: test
-- Level: high
-- Author: Bhabesh Raj
-- Date: 2022-08-02
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects potential sideloading of "mpclient.dll" by Windows Defender processes ("MpCmdRun" and "NisSrv") from their non-default directory.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ImageLoaded ILIKE '%\\mpclient.dll' AND (Image ILIKE '%\\MpCmdRun.exe' OR Image ILIKE '%\\NisSrv.exe')) AND NOT (((Image ILIKE 'C:\\Program Files (x86)\\Windows Defender\\%' OR Image ILIKE 'C:\\Program Files\\Microsoft Security Client\\%' OR Image ILIKE 'C:\\Program Files\\Windows Defender\\%' OR Image ILIKE 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\%' OR Image ILIKE 'C:\\Windows\\WinSxS\\%'))))
