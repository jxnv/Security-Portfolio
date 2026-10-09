// Title: Suspicious Scripting in a WMI Consumer
// ID: fe21810c-2a8c-478f-8dd3-5a287fb2a0e0
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro
// Date: 2019-04-15
// Tags: attack.execution, attack.t1059.005
// Description: Detects suspicious commands that are related to scripting/powershell in WMI Event Consumers
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((Destination contains "new-object" and Destination contains "net.webclient" and Destination contains ".downloadstring")) or ((Destination contains "new-object" and Destination contains "net.webclient" and Destination contains ".downloadfile")) or ((Destination contains " iex(" or Destination contains " -nop " or Destination contains " -noprofile " or Destination contains " -decode " or Destination contains " -enc " or Destination contains "WScript.Shell" or Destination contains "System.Security.Cryptography.FromBase64Transform")))
