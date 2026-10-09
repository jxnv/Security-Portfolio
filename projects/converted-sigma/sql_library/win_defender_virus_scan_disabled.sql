-- Title: Windows Defender Virus Scanning Feature Disabled
-- ID: 686c0b4b-9dd3-4847-9077-d6c1bbe36fcb
-- Status: stable
-- Level: high
-- Author: Ján Trenčanský, frack113
-- Date: 2020-07-28
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects disabling of the Windows Defender virus scanning feature
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (EventID = 5012)
