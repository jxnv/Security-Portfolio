-- Title: Potentially Suspicious Electron Application CommandLine
-- ID: 378a05d8-963c-46c9-bcce-13c7657eac99
-- Status: test
-- Level: medium
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-09-05
-- Tags: attack.execution
-- Description: Detects potentially suspicious CommandLine of electron apps (teams, discord, slack, etc.). This could be a sign of abuse to proxy execution through a signed binary.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%--browser-subprocess-path%' OR CommandLine ILIKE '%--gpu-launcher%' OR CommandLine ILIKE '%--renderer-cmd-prefix%' OR CommandLine ILIKE '%--utility-cmd-prefix%')) AND (((Image ILIKE '%\\chrome.exe' OR Image ILIKE '%\\code.exe' OR Image ILIKE '%\\discord.exe' OR Image ILIKE '%\\GitHubDesktop.exe' OR Image ILIKE '%\\keybase.exe' OR Image ILIKE '%\\msedge_proxy.exe' OR Image ILIKE '%\\msedge.exe' OR Image ILIKE '%\\msedgewebview2.exe' OR Image ILIKE '%\\msteams.exe' OR Image ILIKE '%\\slack.exe' OR Image ILIKE '%\\Teams.exe')) OR ((OriginalFileName = 'chrome.exe' OR OriginalFileName = 'code.exe' OR OriginalFileName = 'discord.exe' OR OriginalFileName = 'GitHubDesktop.exe' OR OriginalFileName = 'keybase.exe' OR OriginalFileName = 'msedge_proxy.exe' OR OriginalFileName = 'msedge.exe' OR OriginalFileName = 'msedgewebview2.exe' OR OriginalFileName = 'msteams.exe' OR OriginalFileName = 'slack.exe' OR OriginalFileName = 'Teams.exe'))))
