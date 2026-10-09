-- Title: Potentially Suspicious Execution Of PDQDeployRunner
-- ID: 12b8e9f5-96b2-41e1-9a42-8c6779a5c184
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-22
-- Tags: attack.execution
-- Description: Detects suspicious execution of "PDQDeployRunner" which is part of the PDQDeploy service stack that is responsible for executing commands and packages on a remote machines
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((Image ILIKE '%\\bash.exe' OR Image ILIKE '%\\certutil.exe' OR Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\csc.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\dllhost.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\msiexec.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\scriptrunner.exe' OR Image ILIKE '%\\wmic.exe' OR Image ILIKE '%\\wscript.exe' OR Image ILIKE '%\\wsl.exe')) OR ((Image ILIKE '%:\\ProgramData\\%' OR Image ILIKE '%:\\Users\\Public\\%' OR Image ILIKE '%:\\Windows\\TEMP\\%' OR Image ILIKE '%\\AppData\\Local\\Temp%')) OR ((CommandLine ILIKE '% -decode %' OR CommandLine ILIKE '% -enc %' OR CommandLine ILIKE '% -encodedcommand %' OR CommandLine ILIKE '% -w hidden%' OR CommandLine ILIKE '%DownloadString%' OR CommandLine ILIKE '%FromBase64String%' OR CommandLine ILIKE '%http%' OR CommandLine ILIKE '%iex %' OR CommandLine ILIKE '%Invoke-%'))) AND (ParentImage ILIKE '%\\PDQDeployRunner-%'))
