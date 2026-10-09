// Title: ShimCache Flush
// ID: b0524451-19af-4efa-a46f-562a977f792e
// Status: stable
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-02-01
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects actions that clear the local ShimCache and remove forensic evidence
// Converted by: Sigma Universal SIEM/EDR CLI

((((CommandLine contains "rundll32" AND CommandLine contains "apphelp.dll")) AND ((CommandLine contains "ShimFlushCache" OR CommandLine contains "#250"))) OR (((CommandLine contains "rundll32" AND CommandLine contains "kernel32.dll")) AND ((CommandLine contains "BaseFlushAppcompatCache" OR CommandLine contains "#46"))))
