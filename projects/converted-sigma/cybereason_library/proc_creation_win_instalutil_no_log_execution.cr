// Title: Suspicious Execution of InstallUtil Without Log
// ID: d042284c-a296-4988-9be5-f424fadcc28c
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-01-23
// Tags: attack.stealth
// Description: Uses the .NET InstallUtil.exe application in order to execute image without log
// Converted by: Sigma Universal SIEM/EDR CLI

(Image="*\\InstallUtil.exe" AND Image contains "Microsoft.NET\\Framework" AND (CommandLine contains "/logfile= " AND CommandLine contains "/LogToConsole=false"))
