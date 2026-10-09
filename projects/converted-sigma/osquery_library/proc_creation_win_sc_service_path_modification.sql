-- Title: Suspicious Service Path Modification
-- ID: 138d3531-8793-4f50-a2cd-f291b2863d78
-- Status: test
-- Level: high
-- Author: Victor Sergeev, oscd.community, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2019-10-21
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1543.003
-- Description: Detects service path modification via the "sc" binary to a suspicious command or path
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (Image="*\\sc.exe" AND (CommandLine LIKE '%config%' AND CommandLine LIKE '%binPath%') AND (CommandLine LIKE '%powershell%' OR CommandLine LIKE '%cmd %' OR CommandLine LIKE '%mshta%' OR CommandLine LIKE '%wscript%' OR CommandLine LIKE '%cscript%' OR CommandLine LIKE '%rundll32%' OR CommandLine LIKE '%svchost%' OR CommandLine LIKE '%dllhost%' OR CommandLine LIKE '%cmd.exe /c%' OR CommandLine LIKE '%cmd.exe /k%' OR CommandLine LIKE '%cmd.exe /r%' OR CommandLine LIKE '%cmd /c%' OR CommandLine LIKE '%cmd /k%' OR CommandLine LIKE '%cmd /r%' OR CommandLine LIKE '%C:\\Users\\Public%' OR CommandLine LIKE '%\\Downloads\\%' OR CommandLine LIKE '%\\Desktop\\%' OR CommandLine LIKE '%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%' OR CommandLine LIKE '%C:\\Windows\\TEMP\\%' OR CommandLine LIKE '%\\AppData\\Local\\Temp%'))
