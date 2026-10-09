-- Title: Process Monitor Driver Creation By Non-Sysinternals Binary
-- ID: a05baa88-e922-4001-bc4d-8738135f27de
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-05
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1068
-- Description: Detects creation of the Process Monitor driver by processes other than Process Monitor (procmon) itself.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetFilename ILIKE '%\\procmon%' AND TargetFilename ILIKE '%.sys') AND NOT (((Image ILIKE '%\\procmon.exe' OR Image ILIKE '%\\procmon64.exe' OR Image ILIKE '%\\procmon64a.exe'))))
