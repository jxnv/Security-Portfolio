-- Title: Potentially Suspicious Network Connection To Notion API
-- ID: 7e9cf7b6-e827-11ed-a05b-15959c120003
-- Status: test
-- Level: low
-- Author: Gavin Knapp
-- Date: 2023-05-03
-- Tags: attack.command-and-control, attack.t1102
-- Description: Detects a non-browser process communicating with the Notion API. This could indicate potential use of a covert C2 channel such as "OffensiveNotion C2"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((DestinationHostname ILIKE '%api.notion.com%') AND NOT (((Image ILIKE '%\\brave.exe') OR ((Image = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe' OR Image = 'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe')) OR ((Image ILIKE 'C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\%') OR (Image ILIKE '%\\WindowsApps\\MicrosoftEdge.exe') OR ((Image = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe' OR Image = 'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe'))) OR ((Image ILIKE 'C:\\Program Files (x86)\\Microsoft\\EdgeCore\\%' OR Image ILIKE 'C:\\Program Files\\Microsoft\\EdgeCore\\%') AND (Image ILIKE '%\\msedge.exe' OR Image ILIKE '%\\msedgewebview2.exe')) OR ((Image = 'C:\\Program Files\\Mozilla Firefox\\firefox.exe' OR Image = 'C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe')) OR ((Image = 'C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe' OR Image = 'C:\\Program Files\\Internet Explorer\\iexplore.exe')) OR (Image ILIKE '%\\maxthon.exe') OR (Image ILIKE '%\\AppData\\Local\\Programs\\Notion\\Notion.exe') OR (Image ILIKE '%\\opera.exe') OR (Image ILIKE '%\\safari.exe') OR (Image ILIKE '%\\seamonkey.exe') OR (Image ILIKE '%\\vivaldi.exe') OR (Image ILIKE '%\\whale.exe'))))
