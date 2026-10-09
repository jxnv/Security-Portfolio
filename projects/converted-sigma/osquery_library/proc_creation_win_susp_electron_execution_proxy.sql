-- Title: Potentially Suspicious Electron Application CommandLine
-- ID: 378a05d8-963c-46c9-bcce-13c7657eac99
-- Status: test
-- Level: medium
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-09-05
-- Tags: attack.execution
-- Description: Detects potentially suspicious CommandLine of electron apps (teams, discord, slack, etc.). This could be a sign of abuse to proxy execution through a signed binary.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%--browser-subprocess-path%' OR CommandLine LIKE '%--gpu-launcher%' OR CommandLine LIKE '%--renderer-cmd-prefix%' OR CommandLine LIKE '%--utility-cmd-prefix%')) AND (((Image="*\\chrome.exe" OR Image="*\\code.exe" OR Image="*\\discord.exe" OR Image="*\\GitHubDesktop.exe" OR Image="*\\keybase.exe" OR Image="*\\msedge_proxy.exe" OR Image="*\\msedge.exe" OR Image="*\\msedgewebview2.exe" OR Image="*\\msteams.exe" OR Image="*\\slack.exe" OR Image="*\\Teams.exe")) OR ((OriginalFileName = 'chrome.exe' OR OriginalFileName = 'code.exe' OR OriginalFileName = 'discord.exe' OR OriginalFileName = 'GitHubDesktop.exe' OR OriginalFileName = 'keybase.exe' OR OriginalFileName = 'msedge_proxy.exe' OR OriginalFileName = 'msedge.exe' OR OriginalFileName = 'msedgewebview2.exe' OR OriginalFileName = 'msteams.exe' OR OriginalFileName = 'slack.exe' OR OriginalFileName = 'Teams.exe'))))
