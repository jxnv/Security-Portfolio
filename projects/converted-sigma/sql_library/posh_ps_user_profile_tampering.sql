-- Title: Potential Persistence Via PowerShell User Profile Using Add-Content
-- ID: 05b3e303-faf0-4f4a-9b30-46cc13e69152
-- Status: test
-- Level: medium
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-08-18
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1546.013
-- Description: Detects calls to "Add-Content" cmdlet in order to modify the content of the user profile and potentially adding suspicious commands for persistence
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ScriptBlockText ILIKE '%Add-Content $profile%') AND ((ScriptBlockText ILIKE '%-Value \"IEX %' OR ScriptBlockText ILIKE '%-Value \"Invoke-Expression%' OR ScriptBlockText ILIKE '%-Value \"Invoke-WebRequest%' OR ScriptBlockText ILIKE '%-Value \"Start-Process%' OR ScriptBlockText ILIKE '%-Value 'IEX %' OR ScriptBlockText ILIKE '%-Value 'Invoke-Expression%' OR ScriptBlockText ILIKE '%-Value 'Invoke-WebRequest%' OR ScriptBlockText ILIKE '%-Value 'Start-Process%')))
