-- Title: Potentially Suspicious Image Load of Offreg.dll
-- ID: c9e5f013-4a6f-4d8c-9b0e-f7a4c3d26e95
-- Status: experimental
-- Level: medium
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2026-07-23
-- Tags: attack.defense-impairment, attack.persistence, attack.t1112
-- Description: Detects potentially suspicious loading of the Offline Registry Library (offreg.dll).
-- Offreg.dll enables direct read/write access to offline registry hives without invoking the Windows Registry API,
-- bypassing its associated audit logging and telemetry. Attackers may abuse this to stealthily modify registry hives
-- while evading detection mechanisms that rely on standard registry event logs.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ImageLoaded ILIKE '%\\offreg.dll') AND NOT (((Image ILIKE 'C:\\Users\\%' AND Image ILIKE '%\\AppData\\Local\\Programs\\%') OR (Image ILIKE 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\%' AND Image ILIKE '%\\MsMpEng.exe') OR ((Image ILIKE 'C:\\Program Files\\%' OR Image ILIKE 'C:\\Program Files (x86)\\%')) OR ((Image ILIKE 'C:\\Windows\\System32\\%' OR Image ILIKE 'C:\\Windows\\SysWOW64\\%' OR Image ILIKE 'C:\\Windows\\WinSxS\\%')))))
