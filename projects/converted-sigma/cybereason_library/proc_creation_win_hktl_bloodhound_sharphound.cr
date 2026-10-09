// Title: HackTool - Bloodhound/Sharphound Execution
// ID: f376c8a7-a2d0-4ddc-aa0c-16c17236d962
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2019-12-20
// Tags: attack.discovery, attack.t1087.001, attack.t1087.002, attack.t1482, attack.t1069.001, attack.t1069.002, attack.execution, attack.t1059.001
// Description: Detects command line parameters used by Bloodhound and Sharphound hack tools
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains " -CollectionMethod All " OR CommandLine contains " --CollectionMethods Session " OR CommandLine contains " --Loop --Loopduration " OR CommandLine contains " --PortScanTimeout " OR CommandLine contains ".exe -c All -d " OR CommandLine contains "Invoke-Bloodhound" OR CommandLine contains "Get-BloodHoundData")) OR ((CommandLine contains " -JsonFolder " AND CommandLine contains " -ZipFileName ")) OR ((CommandLine contains " DCOnly " AND CommandLine contains " --NoSaveCache ")) OR ((Product contains "SharpHound") OR (Description contains "SharpHound") OR ((Company contains "SpecterOps" OR Company contains "evil corp")) OR ((Image contains "\\Bloodhound.exe" OR Image contains "\\SharpHound.exe"))))
