-- Title: Potentially Suspicious Execution Of Regasm/Regsvcs With Uncommon Extension
-- ID: e9f8f8cc-07cc-4e81-b724-f387db9175e4
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-02-13
-- Tags: attack.stealth, attack.t1218.009
-- Description: Detects potentially suspicious execution of the Regasm/Regsvcs utilities with an uncommon extension.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%.dat%' OR CommandLine ILIKE '%.gif%' OR CommandLine ILIKE '%.jpeg%' OR CommandLine ILIKE '%.jpg%' OR CommandLine ILIKE '%.png%' OR CommandLine ILIKE '%.txt%')) AND (((Image ILIKE '%\\Regsvcs.exe' OR Image ILIKE '%\\Regasm.exe')) OR ((OriginalFileName = 'RegSvcs.exe' OR OriginalFileName = 'RegAsm.exe'))))
