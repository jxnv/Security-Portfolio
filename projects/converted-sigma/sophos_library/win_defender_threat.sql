-- Title: Windows Defender Threat Detected
-- ID: 57b649ef-ff42-4fb0-8bf6-62da243a1708
-- Status: stable
-- Level: high
-- Author: Ján Trenčanský
-- Date: 2020-07-28
-- Tags: attack.execution, attack.t1059
-- Description: Detects actions taken by Windows Defender malware detection engines
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((EventID = 1006 OR EventID = 1015 OR EventID = 1116 OR EventID = 1117))
