-- Title: Kavremover Dropped Binary LOLBIN Usage
-- ID: d047726b-c71c-4048-a99b-2e2f50dc107d
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-11-01
-- Tags: attack.execution, attack.stealth, attack.t1127
-- Description: Detects the execution of a signed binary dropped by Kaspersky Lab Products Remover (kavremover) which can be abused as a LOLBIN to execute arbitrary commands and binaries.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '% run run-cmd %') AND NOT (((ParentImage ILIKE '%\\cleanapi.exe' OR ParentImage ILIKE '%\\kavremover.exe'))))
