-- Title: Boot Configuration Tampering Via Bcdedit.EXE
-- ID: 1444443e-6757-43e4-9ea4-c8fc705f79a2
-- Status: stable
-- Level: high
-- Author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
-- Date: 2019-10-24
-- Tags: attack.impact, attack.t1490
-- Description: Detects the use of the bcdedit command to tamper with the boot configuration data. This technique is often times used by malware or attackers as a destructive way before launching ransomware.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%bootstatuspolicy%' AND CommandLine LIKE '%ignoreallfailures%')) OR ((CommandLine LIKE '%recoveryenabled%' AND CommandLine LIKE '%no%'))) AND ((Image="*\\bcdedit.exe") OR (OriginalFileName = 'bcdedit.exe')) AND (CommandLine LIKE '%set%'))
