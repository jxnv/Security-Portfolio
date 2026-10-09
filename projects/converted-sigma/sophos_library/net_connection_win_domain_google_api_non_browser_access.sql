-- Title: Suspicious Non-Browser Network Communication With Google API
-- ID: 7e9cf7b6-e827-11ed-a05b-0242ac120003
-- Status: experimental
-- Level: medium
-- Author: Gavin Knapp
-- Date: 2023-05-01
-- Tags: attack.command-and-control, attack.t1102
-- Description: Detects a non-browser process interacting with the Google API which could indicate the use of a covert C2 such as Google Sheet C2 (GC2-sheet)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((DestinationHostname ILIKE '%drive.googleapis.com%' OR DestinationHostname ILIKE '%oauth2.googleapis.com%' OR DestinationHostname ILIKE '%sheets.googleapis.com%' OR DestinationHostname ILIKE '%www.googleapis.com%')) AND NOT (((Image = '') OR (Image IS NULL))) AND NOT (((Image ILIKE '%\\brave.exe') OR ((Image ILIKE '%:\\Program Files\\Google\\Chrome\\Application\\chrome.exe' OR Image ILIKE '%:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe')) OR ((Image ILIKE '%:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\%') OR ((Image ILIKE '%:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe' OR Image ILIKE '%:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe' OR Image ILIKE '%\\WindowsApps\\MicrosoftEdge.exe'))) OR ((Image ILIKE '%:\\Program Files (x86)\\Microsoft\\EdgeCore\\%' OR Image ILIKE '%:\\Program Files\\Microsoft\\EdgeCore\\%') AND (Image ILIKE '%\\msedge.exe' OR Image ILIKE '%\\msedgewebview2.exe')) OR ((Image ILIKE '%:\\Program Files\\Mozilla Firefox\\firefox.exe' OR Image ILIKE '%:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe')) OR (Image ILIKE '%:\\Program Files\\Google\\Drive File Stream\\%' AND Image ILIKE '%\\GoogleDriveFS.exe') OR (Image ILIKE '%\\GoogleUpdate.exe') OR ((Image ILIKE '%:\\Program Files (x86)\\Internet Explorer\\iexplore.exe' OR Image ILIKE '%:\\Program Files\\Internet Explorer\\iexplore.exe')) OR (Image ILIKE '%\\maxthon.exe') OR (Image ILIKE '%\\opera.exe') OR (Image ILIKE '%\\outlook.exe') OR (Image ILIKE '%\\safari.exe') OR (Image ILIKE '%\\seamonkey.exe') OR (Image ILIKE '%\\vivaldi.exe') OR (Image ILIKE '%\\whale.exe'))))
