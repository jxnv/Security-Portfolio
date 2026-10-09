-- Title: HackTool - Bloodhound/Sharphound Execution
-- ID: f376c8a7-a2d0-4ddc-aa0c-16c17236d962
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2019-12-20
-- Tags: attack.discovery, attack.t1087.001, attack.t1087.002, attack.t1482, attack.t1069.001, attack.t1069.002, attack.execution, attack.t1059.001
-- Description: Detects command line parameters used by Bloodhound and Sharphound hack tools
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% -CollectionMethod All %' OR CommandLine LIKE '% --CollectionMethods Session %' OR CommandLine LIKE '% --Loop --Loopduration %' OR CommandLine LIKE '% --PortScanTimeout %' OR CommandLine LIKE '%.exe -c All -d %' OR CommandLine LIKE '%Invoke-Bloodhound%' OR CommandLine LIKE '%Get-BloodHoundData%')) OR ((CommandLine LIKE '% -JsonFolder %' AND CommandLine LIKE '% -ZipFileName %')) OR ((CommandLine LIKE '% DCOnly %' AND CommandLine LIKE '% --NoSaveCache %')) OR ((Product LIKE '%SharpHound%') OR (Description LIKE '%SharpHound%') OR ((Company LIKE '%SpecterOps%' OR Company LIKE '%evil corp%')) OR ((Image LIKE '%\\Bloodhound.exe%' OR Image LIKE '%\\SharpHound.exe%'))))
