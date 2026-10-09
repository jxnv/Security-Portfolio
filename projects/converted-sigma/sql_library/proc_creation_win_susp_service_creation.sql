-- Title: Suspicious New Service Creation
-- ID: 17a1be64-8d88-40bf-b5ff-a4f7a50ebcc8
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-14
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1543.003
-- Description: Detects creation of a new service via "sc" command or the powershell "new-service" cmdlet with suspicious binary paths
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((CommandLine ILIKE '%New-Service%' AND CommandLine ILIKE '%-BinaryPathName%')) OR (Image ILIKE '%\\sc.exe' AND (CommandLine ILIKE '%create%' AND CommandLine ILIKE '%binPath=%'))) AND ((CommandLine ILIKE '%powershell%' OR CommandLine ILIKE '%mshta%' OR CommandLine ILIKE '%wscript%' OR CommandLine ILIKE '%cscript%' OR CommandLine ILIKE '%svchost%' OR CommandLine ILIKE '%dllhost%' OR CommandLine ILIKE '%cmd %' OR CommandLine ILIKE '%cmd.exe /c%' OR CommandLine ILIKE '%cmd.exe /k%' OR CommandLine ILIKE '%cmd.exe /r%' OR CommandLine ILIKE '%rundll32%' OR CommandLine ILIKE '%C:\\Users\\Public%' OR CommandLine ILIKE '%\\Downloads\\%' OR CommandLine ILIKE '%\\Desktop\\%' OR CommandLine ILIKE '%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%' OR CommandLine ILIKE '%C:\\Windows\\TEMP\\%' OR CommandLine ILIKE '%\\AppData\\Local\\Temp%')))
