-- Title: User Discovery And Export Via Get-ADUser Cmdlet - PowerShell
-- ID: c2993223-6da8-4b1a-88ee-668b8bf315e9
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-11-17
-- Tags: attack.discovery, attack.t1033
-- Description: Detects usage of the Get-ADUser cmdlet to collect user information and output it to a file
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ScriptBlockText ILIKE '%Get-ADUser %' AND ScriptBlockText ILIKE '% -Filter \\*%') AND (ScriptBlockText ILIKE '% > %' OR ScriptBlockText ILIKE '% | Select %' OR ScriptBlockText ILIKE '%Out-File%' OR ScriptBlockText ILIKE '%Set-Content%' OR ScriptBlockText ILIKE '%Add-Content%'))
