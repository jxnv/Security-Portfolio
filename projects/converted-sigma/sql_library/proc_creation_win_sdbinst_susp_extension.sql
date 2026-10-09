-- Title: Uncommon Extension Shim Database Installation Via Sdbinst.EXE
-- ID: 18ee686c-38a3-4f65-9f44-48a077141f42
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-08-01
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1546.011
-- Description: Detects installation of a potentially suspicious new shim with an uncommon extension using sdbinst.exe.
-- Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\sdbinst.exe') OR (OriginalFileName = 'sdbinst.exe')) AND NOT (((CommandLine = '') OR (CommandLine ILIKE '%.sdb%') OR (((CommandLine ILIKE '% -c' OR CommandLine ILIKE '% -f' OR CommandLine ILIKE '% -mm' OR CommandLine ILIKE '% -t')) OR (CommandLine ILIKE '% -m -bg%')) OR (CommandLine IS NULL))))
