-- Title: Suspicious Non-Browser Network Communication With Telegram API
-- ID: c3dbbc9f-ef1d-470a-a90a-d343448d5875
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-19
-- Tags: attack.command-and-control, attack.exfiltration, attack.t1102, attack.t1567, attack.t1105
-- Description: Detects an a non-browser process interacting with the Telegram API which could indicate use of a covert C2
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((DestinationHostname ILIKE '%api.telegram.org%') AND NOT (((Image ILIKE '%\\brave.exe') OR ((Image = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe' OR Image = 'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe')) OR ((Image ILIKE 'C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\%') OR (Image ILIKE '%\\WindowsApps\\MicrosoftEdge.exe') OR ((Image = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe' OR Image = 'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe'))) OR ((Image ILIKE 'C:\\Program Files (x86)\\Microsoft\\EdgeCore\\%' OR Image ILIKE 'C:\\Program Files\\Microsoft\\EdgeCore\\%') AND (Image ILIKE '%\\msedge.exe' OR Image ILIKE '%\\msedgewebview2.exe')) OR ((Image = 'C:\\Program Files\\Mozilla Firefox\\firefox.exe' OR Image = 'C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe')) OR ((Image = 'C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe' OR Image = 'C:\\Program Files\\Internet Explorer\\iexplore.exe')) OR (Image ILIKE '%\\maxthon.exe') OR (Image ILIKE '%\\opera.exe') OR (Image ILIKE '%\\safari.exe') OR (Image ILIKE '%\\seamonkey.exe') OR (Image ILIKE '%\\vivaldi.exe') OR (Image ILIKE '%\\whale.exe'))))
