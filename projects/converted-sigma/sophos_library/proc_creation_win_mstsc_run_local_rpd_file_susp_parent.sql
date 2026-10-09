-- Title: Mstsc.EXE Execution From Uncommon Parent
-- ID: ff3b6b39-e765-42f9-bb2c-ea6761e0e0f6
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-04-18
-- Tags: attack.lateral-movement
-- Description: Detects potential RDP connection via Mstsc using a local ".rdp" file located in suspicious locations.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Image ILIKE '%\\mstsc.exe') OR (OriginalFileName = 'mstsc.exe')) AND ((ParentImage ILIKE '%\\brave.exe' OR ParentImage ILIKE '%\\CCleanerBrowser.exe' OR ParentImage ILIKE '%\\chrome.exe' OR ParentImage ILIKE '%\\chromium.exe' OR ParentImage ILIKE '%\\firefox.exe' OR ParentImage ILIKE '%\\iexplore.exe' OR ParentImage ILIKE '%\\microsoftedge.exe' OR ParentImage ILIKE '%\\msedge.exe' OR ParentImage ILIKE '%\\opera.exe' OR ParentImage ILIKE '%\\vivaldi.exe' OR ParentImage ILIKE '%\\whale.exe' OR ParentImage ILIKE '%\\outlook.exe')))
