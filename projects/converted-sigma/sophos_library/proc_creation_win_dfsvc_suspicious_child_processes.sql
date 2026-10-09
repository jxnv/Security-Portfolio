-- Title: Potentially Suspicious Child Process Of ClickOnce Application
-- ID: 67bc0e75-c0a9-4cfc-8754-84a505b63c04
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-06-12
-- Tags: attack.execution, attack.stealth
-- Description: Detects potentially suspicious child processes of a ClickOnce deployment application
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (ParentImage ILIKE '%\\AppData\\Local\\Apps\\2.0\\%' AND (Image ILIKE '%\\calc.exe' OR Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\explorer.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\net.exe' OR Image ILIKE '%\\net1.exe' OR Image ILIKE '%\\nltest.exe' OR Image ILIKE '%\\notepad.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\reg.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\schtasks.exe' OR Image ILIKE '%\\werfault.exe' OR Image ILIKE '%\\wscript.exe'))
