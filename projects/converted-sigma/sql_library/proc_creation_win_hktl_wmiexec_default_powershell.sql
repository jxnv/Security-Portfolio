-- Title: HackTool - Wmiexec Default Powershell Command
-- ID: 022eaba8-f0bf-4dd9-9217-4604b0bb3bb0
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-03-08
-- Tags: attack.lateral-movement, attack.stealth
-- Description: Detects the execution of PowerShell with a specific flag sequence that is used by the Wmiexec script
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (CommandLine ILIKE '%-NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc%')
