// Title: Suspicious Scripting in a WMI Consumer
// ID: fe21810c-2a8c-478f-8dd3-5a287fb2a0e0
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro
// Date: 2019-04-15
// Tags: attack.execution, attack.t1059.005
// Description: Detects suspicious commands that are related to scripting/powershell in WMI Event Consumers
// Converted by: Sigma Universal SIEM/EDR CLI

(((Destination contains "new-object" AND Destination contains "net.webclient" AND Destination contains ".downloadstring")) OR ((Destination contains "new-object" AND Destination contains "net.webclient" AND Destination contains ".downloadfile")) OR ((Destination contains " iex(" OR Destination contains " -nop " OR Destination contains " -noprofile " OR Destination contains " -decode " OR Destination contains " -enc " OR Destination contains "WScript.Shell" OR Destination contains "System.Security.Cryptography.FromBase64Transform")))
