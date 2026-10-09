-- Title: Suspicious New Service Creation
-- ID: 17a1be64-8d88-40bf-b5ff-a4f7a50ebcc8
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-14
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1543.003
-- Description: Detects creation of a new service via "sc" command or the powershell "new-service" cmdlet with suspicious binary paths
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%New-Service%' AND CommandLine LIKE '%-BinaryPathName%')) OR (Image="*\\sc.exe" AND (CommandLine LIKE '%create%' AND CommandLine LIKE '%binPath=%'))) AND ((CommandLine LIKE '%powershell%' OR CommandLine LIKE '%mshta%' OR CommandLine LIKE '%wscript%' OR CommandLine LIKE '%cscript%' OR CommandLine LIKE '%svchost%' OR CommandLine LIKE '%dllhost%' OR CommandLine LIKE '%cmd %' OR CommandLine LIKE '%cmd.exe /c%' OR CommandLine LIKE '%cmd.exe /k%' OR CommandLine LIKE '%cmd.exe /r%' OR CommandLine LIKE '%rundll32%' OR CommandLine LIKE '%C:\\Users\\Public%' OR CommandLine LIKE '%\\Downloads\\%' OR CommandLine LIKE '%\\Desktop\\%' OR CommandLine LIKE '%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%' OR CommandLine LIKE '%C:\\Windows\\TEMP\\%' OR CommandLine LIKE '%\\AppData\\Local\\Temp%')))
