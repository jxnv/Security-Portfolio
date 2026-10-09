-- Title: ESXi Syslog Configuration Change Via ESXCLI
-- ID: 38eb1dbb-011f-40b1-a126-cf03a0210563
-- Status: test
-- Level: medium
-- Author: Cedric Maurugeon
-- Date: 2023-09-04
-- Tags: attack.execution, attack.defense-impairment, attack.t1685, attack.t1690, attack.t1059.012
-- Description: Detects changes to the ESXi syslog configuration via "esxcli"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image ILIKE '%/esxcli' AND (CommandLine ILIKE '%system%' AND CommandLine ILIKE '%syslog%' AND CommandLine ILIKE '%config%') AND CommandLine ILIKE '% set%')
