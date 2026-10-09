-- Title: New Firewall Rule Added In Windows Firewall Exception List For Potential Suspicious Application
-- ID: 9e2575e7-2cb9-4da1-adc8-ed94221dca5e
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2023-02-26
-- Tags: attack.defense-impairment, attack.t1686.003
-- Description: Detects the addition of a new rule to the Windows Firewall exception list for an application located in a potentially suspicious location.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((EventID = 2004 OR EventID = 2071 OR EventID = 2097) AND (ApplicationPath ILIKE '%:\\PerfLogs\\%' OR ApplicationPath ILIKE '%:\\Temp\\%' OR ApplicationPath ILIKE '%:\\Tmp\\%' OR ApplicationPath ILIKE '%:\\Users\\Public\\%' OR ApplicationPath ILIKE '%:\\Windows\\Tasks\\%' OR ApplicationPath ILIKE '%:\\Windows\\Temp\\%' OR ApplicationPath ILIKE '%\\AppData\\Local\\Temp\\%')) AND NOT ((Action = 2)))
