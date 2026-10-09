-- Title: WMIC Unquoted Services Path Lookup - PowerShell
-- ID: 09658312-bc27-4a3b-91c5-e49ab9046d1b
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-06-20
-- Tags: attack.execution, attack.t1047
-- Description: Detects known WMI recon method to look for unquoted service paths, often used by pentest inside of powershell scripts attackers enum scripts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((ScriptBlockText LIKE '%Get-WmiObject %' OR ScriptBlockText LIKE '%gwmi %') AND (ScriptBlockText LIKE '% Win32_Service %' AND ScriptBlockText LIKE '%Name%' AND ScriptBlockText LIKE '%DisplayName%' AND ScriptBlockText LIKE '%PathName%' AND ScriptBlockText LIKE '%StartMode%'))
