-- Title: Potentially Suspicious Execution Of PDQDeployRunner
-- ID: 12b8e9f5-96b2-41e1-9a42-8c6779a5c184
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-22
-- Tags: attack.execution
-- Description: Detects suspicious execution of "PDQDeployRunner" which is part of the PDQDeploy service stack that is responsible for executing commands and packages on a remote machines
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((Image="*\\bash.exe" OR Image="*\\certutil.exe" OR Image="*\\cmd.exe" OR Image="*\\csc.exe" OR Image="*\\cscript.exe" OR Image="*\\dllhost.exe" OR Image="*\\mshta.exe" OR Image="*\\msiexec.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\scriptrunner.exe" OR Image="*\\wmic.exe" OR Image="*\\wscript.exe" OR Image="*\\wsl.exe")) OR ((Image LIKE '%:\\ProgramData\\%' OR Image LIKE '%:\\Users\\Public\\%' OR Image LIKE '%:\\Windows\\TEMP\\%' OR Image LIKE '%\\AppData\\Local\\Temp%')) OR ((CommandLine LIKE '% -decode %' OR CommandLine LIKE '% -enc %' OR CommandLine LIKE '% -encodedcommand %' OR CommandLine LIKE '% -w hidden%' OR CommandLine LIKE '%DownloadString%' OR CommandLine LIKE '%FromBase64String%' OR CommandLine LIKE '%http%' OR CommandLine LIKE '%iex %' OR CommandLine LIKE '%Invoke-%'))) AND (ParentImage LIKE '%\\PDQDeployRunner-%'))
