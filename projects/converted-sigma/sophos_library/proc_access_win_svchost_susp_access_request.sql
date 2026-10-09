-- Title: Suspicious Svchost Process Access
-- ID: 166e9c50-8cd9-44af-815d-d1f0c0e90dde
-- Status: test
-- Level: high
-- Author: Tim Burrell
-- Date: 2020-01-02
-- Tags: attack.defense-impairment, attack.t1685.001
-- Description: Detects suspicious access to the "svchost" process such as that used by Invoke-Phantom to kill the thread of the Windows event logging service.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetImage ILIKE '%:\\Windows\\System32\\svchost.exe' AND GrantedAccess = '0x1F3FFF' AND CallTrace ILIKE '%UNKNOWN%') AND NOT ((SourceImage ILIKE '%:\\Program Files\\Microsoft Visual Studio\\%' AND SourceImage ILIKE '%\\MSBuild\\Current\\Bin\\MSBuild.exe' AND (CallTrace ILIKE '%Microsoft.Build.ni.dll%' OR CallTrace ILIKE '%System.ni.dll%'))))
