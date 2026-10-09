-- Title: WMIC Unquoted Services Path Lookup - PowerShell
-- ID: 09658312-bc27-4a3b-91c5-e49ab9046d1b
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-06-20
-- Tags: attack.execution, attack.t1047
-- Description: Detects known WMI recon method to look for unquoted service paths, often used by pentest inside of powershell scripts attackers enum scripts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ScriptBlockText ILIKE '%Get-WmiObject %' OR ScriptBlockText ILIKE '%gwmi %') AND (ScriptBlockText ILIKE '% Win32_Service %' AND ScriptBlockText ILIKE '%Name%' AND ScriptBlockText ILIKE '%DisplayName%' AND ScriptBlockText ILIKE '%PathName%' AND ScriptBlockText ILIKE '%StartMode%'))
