-- Title: WMI Persistence - Command Line Event Consumer
-- ID: 05936ce2-ee05-4dae-9d03-9a391cf2d2c6
-- Status: test
-- Level: high
-- Author: Thomas Patzke
-- Date: 2018-03-07
-- Tags: attack.privilege-escalation, attack.t1546.003, attack.persistence
-- Description: Detects WMI command line event consumers
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image = 'C:\\Windows\\System32\\wbem\\WmiPrvSE.exe' AND ImageLoaded ILIKE '%\\wbemcons.dll')
