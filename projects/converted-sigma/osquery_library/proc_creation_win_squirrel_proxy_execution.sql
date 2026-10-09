-- Title: Process Proxy Execution Via Squirrel.EXE
-- ID: 45239e6a-b035-4aaf-b339-8ad379fcb67e
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), Karneades / Markus Neis, Jonhnathan Ribeiro, oscd.community
-- Date: 2022-06-09
-- Tags: attack.execution, attack.stealth, attack.t1218
-- Description: Detects the usage of the "Squirrel.exe" binary to execute arbitrary processes. This binary is part of multiple Electron based software installations (Slack, Teams, Discord, etc.)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%--processStart%' OR CommandLine LIKE '%--processStartAndWait%' OR CommandLine LIKE '%--createShortcut%')) AND ((Image="*\\squirrel.exe" OR Image="*\\update.exe"))) AND NOT ((((CommandLine LIKE '%:\\Users\\%' AND CommandLine LIKE '%\\AppData\\Local\\Discord\\Update.exe%' AND CommandLine LIKE '%Discord.exe%') AND (CommandLine LIKE '%--createShortcut%' OR CommandLine LIKE '%--processStart%')) OR ((CommandLine LIKE '%:\\Users\\%' AND CommandLine LIKE '%\\AppData\\Local\\GitHubDesktop\\Update.exe%' AND CommandLine LIKE '%GitHubDesktop.exe%') AND (CommandLine LIKE '%--createShortcut%' OR CommandLine LIKE '%--processStartAndWait%')) OR ((CommandLine LIKE '%:\\Users\\%' AND CommandLine LIKE '%\\AppData\\Local\\Microsoft\\Teams\\Update.exe%' AND CommandLine LIKE '%Teams.exe%') AND (CommandLine LIKE '%--processStart%' OR CommandLine LIKE '%--createShortcut%')) OR ((CommandLine LIKE '%:\\Users\\%' AND CommandLine LIKE '%\\AppData\\Local\\yammerdesktop\\Update.exe%' AND CommandLine LIKE '%Yammer.exe%') AND (CommandLine LIKE '%--processStart%' OR CommandLine LIKE '%--createShortcut%')))))
