-- Title: Potential Suspicious Winget Package Installation
-- ID: a3f5c081-e75b-43a0-9f5b-51f26fe5dba2
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-04-18
-- Tags: attack.persistence, attack.stealth
-- Description: Detects potential suspicious winget package installation from a suspicious source.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Contents ILIKE '[ZoneTransfer]  ZoneId=3%' AND (Contents ILIKE '%://1%' OR Contents ILIKE '%://2%' OR Contents ILIKE '%://3%' OR Contents ILIKE '%://4%' OR Contents ILIKE '%://5%' OR Contents ILIKE '%://6%' OR Contents ILIKE '%://7%' OR Contents ILIKE '%://8%' OR Contents ILIKE '%://9%') AND TargetFilename ILIKE '%:Zone.Identifier' AND TargetFilename ILIKE '%\\AppData\\Local\\Temp\\WinGet\\%')
