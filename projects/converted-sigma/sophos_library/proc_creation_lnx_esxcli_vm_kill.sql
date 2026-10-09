-- Title: ESXi VM Kill Via ESXCLI
-- ID: 2992ac4d-31e9-4325-99f2-b18a73221bb2
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), Cedric Maurugeon
-- Date: 2023-09-04
-- Tags: attack.execution, attack.impact, attack.t1059.012, attack.t1529
-- Description: Detects execution of the "esxcli" command with the "vm" and "kill" flag in order to kill/shutdown a specific VM.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image ILIKE '%/esxcli' AND (CommandLine ILIKE '%vm process%' AND CommandLine ILIKE '%kill%'))
