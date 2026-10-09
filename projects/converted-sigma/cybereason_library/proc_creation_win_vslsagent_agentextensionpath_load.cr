// Title: Suspicious Vsls-Agent Command With AgentExtensionPath Load
// ID: 43103702-5886-11ed-9b6a-0242ac120002
// Status: test
// Level: medium
// Author: bohops
// Date: 2022-10-30
// Tags: attack.stealth, attack.t1218
// Description: Detects Microsoft Visual Studio vsls-agent.exe lolbin execution with a suspicious library load using the --agentExtensionPath parameter
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\vsls-agent.exe" AND CommandLine contains "--agentExtensionPath") AND NOT ((CommandLine contains "Microsoft.VisualStudio.LiveShare.Agent.")))
