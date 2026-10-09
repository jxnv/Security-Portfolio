// Title: Shell Process Spawned by Java.EXE
// ID: dff1e1cc-d3fd-47c8-bfc2-aeb878a754c0
// Status: test
// Level: medium
// Author: Andreas Hunkeler (@Karneades), Nasreddine Bencherchali
// Date: 2021-12-17
// Tags: attack.initial-access, attack.persistence, attack.privilege-escalation
// Description: Detects shell spawned from Java host process, which could be a sign of exploitation (e.g. log4j exploitation)
// Converted by: Sigma Universal SIEM/EDR CLI

((ParentImage="*\\java.exe" AND (Image="*\\bash.exe" OR Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) AND NOT ((ParentImage: "*build*" AND CommandLine: "*build*")))
