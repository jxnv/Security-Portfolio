// Title: Potentially Suspicious Execution Of PDQDeployRunner
// ID: 12b8e9f5-96b2-41e1-9a42-8c6779a5c184
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-22
// Tags: attack.execution
// Description: Detects suspicious execution of "PDQDeployRunner" which is part of the PDQDeploy service stack that is responsible for executing commands and packages on a remote machines
// Converted by: Sigma Universal SIEM/EDR CLI

((((Image="*\\bash.exe" OR Image="*\\certutil.exe" OR Image="*\\cmd.exe" OR Image="*\\csc.exe" OR Image="*\\cscript.exe" OR Image="*\\dllhost.exe" OR Image="*\\mshta.exe" OR Image="*\\msiexec.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\scriptrunner.exe" OR Image="*\\wmic.exe" OR Image="*\\wscript.exe" OR Image="*\\wsl.exe")) OR ((Image contains ":\\ProgramData\\" OR Image contains ":\\Users\\Public\\" OR Image contains ":\\Windows\\TEMP\\" OR Image contains "\\AppData\\Local\\Temp")) OR ((CommandLine contains " -decode " OR CommandLine contains " -enc " OR CommandLine contains " -encodedcommand " OR CommandLine contains " -w hidden" OR CommandLine contains "DownloadString" OR CommandLine contains "FromBase64String" OR CommandLine contains "http" OR CommandLine contains "iex " OR CommandLine contains "Invoke-"))) AND (ParentImage contains "\\PDQDeployRunner-"))
