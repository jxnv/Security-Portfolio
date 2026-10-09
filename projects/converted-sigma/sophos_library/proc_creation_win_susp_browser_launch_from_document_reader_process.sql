-- Title: Potential Suspicious Browser Launch From Document Reader Process
-- ID: 1193d960-2369-499f-a158-7b50a31df682
-- Status: test
-- Level: medium
-- Author: Joseph Kamau
-- Date: 2024-05-27
-- Tags: attack.execution, attack.t1204.002
-- Description: Detects when a browser process or browser tab is launched from an application that handles document files such as Adobe, Microsoft Office, etc. And connects to a web application over http(s), this could indicate a possible phishing attempt.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((ParentImage ILIKE '%Acrobat Reader%' OR ParentImage ILIKE '%Microsoft Office%' OR ParentImage ILIKE '%PDF Reader%') AND (Image ILIKE '%\\brave.exe' OR Image ILIKE '%\\chrome.exe' OR Image ILIKE '%\\firefox.exe' OR Image ILIKE '%\\msedge.exe' OR Image ILIKE '%\\opera.exe' OR Image ILIKE '%\\maxthon.exe' OR Image ILIKE '%\\seamonkey.exe' OR Image ILIKE '%\\vivaldi.exe') AND CommandLine ILIKE '%http%') AND NOT ((CommandLine ILIKE '%https://go.microsoft.com/fwlink/%')) AND NOT (((CommandLine ILIKE '%http://ad.foxitsoftware.com/adlog.php?%' OR CommandLine ILIKE '%https://globe-map.foxitservice.com/go.php?do=redirect%'))))
