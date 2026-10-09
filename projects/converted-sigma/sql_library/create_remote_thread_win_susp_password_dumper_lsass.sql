-- Title: Password Dumper Remote Thread in LSASS
-- ID: f239b326-2f41-4d6b-9dfa-c846a60ef505
-- Status: stable
-- Level: high
-- Author: Thomas Patzke
-- Date: 2017-02-19
-- Tags: attack.credential-access, attack.s0005, attack.t1003.001
-- Description: Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage.
-- The process in field Process is the malicious program. A single execution can lead to hundreds of events.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (TargetImage ILIKE '%\\lsass.exe' AND StartModule = '')
