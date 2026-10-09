// Title: Suspicious Debugger Registration Cmdline
// ID: ae215552-081e-44c7-805f-be16f975c8a2
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), oscd.community, Jonhnathan Ribeiro
// Date: 2019-09-06
// Tags: attack.persistence, attack.privilege-escalation, attack.t1546.008
// Description: Detects the registration of a debugger for a program that is available in the logon screen (sticky key backdoor).
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine contains "\\CurrentVersion\\Image File Execution Options\\") AND ((CommandLine contains "sethc.exe" OR CommandLine contains "utilman.exe" OR CommandLine contains "osk.exe" OR CommandLine contains "magnify.exe" OR CommandLine contains "narrator.exe" OR CommandLine contains "displayswitch.exe" OR CommandLine contains "atbroker.exe" OR CommandLine contains "HelpPane.exe")))
