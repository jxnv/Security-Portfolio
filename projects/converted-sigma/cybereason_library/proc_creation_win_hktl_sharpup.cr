// Title: HackTool - SharpUp PrivEsc Tool Execution
// ID: c484e533-ee16-4a93-b6ac-f0ea4868b2f1
// Status: test
// Level: critical
// Author: Florian Roth (Nextron Systems)
// Date: 2022-08-20
// Tags: attack.persistence, attack.privilege-escalation, attack.discovery, attack.execution, attack.stealth, attack.t1615, attack.t1569.002, attack.t1574.005
// Description: Detects the use of SharpUp, a tool for local privilege escalation
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\SharpUp.exe") OR (Description == "SharpUp") OR ((CommandLine contains "HijackablePaths" OR CommandLine contains "UnquotedServicePath" OR CommandLine contains "ProcessDLLHijack" OR CommandLine contains "ModifiableServiceBinaries" OR CommandLine contains "ModifiableScheduledTask" OR CommandLine contains "DomainGPPPassword" OR CommandLine contains "CachedGPPPassword")))
