// Title: HackTool - CrackMapExec Process Patterns
// ID: f26307d8-14cd-47e3-a26b-4b4769f24af6
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-03-12
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects suspicious process patterns found in logs when CrackMapExec is used
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "tasklist /fi " AND CommandLine contains "Imagename eq lsass.exe") AND (CommandLine contains "cmd.exe /c " OR CommandLine contains "cmd.exe /r " OR CommandLine contains "cmd.exe /k " OR CommandLine contains "cmd /c " OR CommandLine contains "cmd /r " OR CommandLine contains "cmd /k ") AND (User contains "AUTHORI" OR User contains "AUTORI")) OR ((CommandLine contains "do rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump" AND CommandLine contains "\\Windows\\Temp\\" AND CommandLine contains " full" AND CommandLine contains "%%B")) OR ((CommandLine contains "tasklist /v /fo csv" AND CommandLine contains "findstr /i \"lsass\"")))
