-- Title: Chromium Browser Instance Executed With Custom Extension
-- ID: 88d6e60c-759d-4ac1-a447-c0f1466c2d21
-- Status: test
-- Level: medium
-- Author: Aedan Russell, frack113, X__Junior (Nextron Systems)
-- Date: 2022-06-19
-- Tags: attack.persistence, attack.t1176.001
-- Description: Detects a Chromium based browser process with the 'load-extension' flag to start a instance with a custom extension
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\brave.exe' OR Image ILIKE '%\\chrome.exe' OR Image ILIKE '%\\msedge.exe' OR Image ILIKE '%\\opera.exe' OR Image ILIKE '%\\vivaldi.exe') AND CommandLine ILIKE '%--load-extension=%')
