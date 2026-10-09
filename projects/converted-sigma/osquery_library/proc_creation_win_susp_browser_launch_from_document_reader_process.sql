-- Title: Potential Suspicious Browser Launch From Document Reader Process
-- ID: 1193d960-2369-499f-a158-7b50a31df682
-- Status: test
-- Level: medium
-- Author: Joseph Kamau
-- Date: 2024-05-27
-- Tags: attack.execution, attack.t1204.002
-- Description: Detects when a browser process or browser tab is launched from an application that handles document files such as Adobe, Microsoft Office, etc. And connects to a web application over http(s), this could indicate a possible phishing attempt.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((ParentImage LIKE '%Acrobat Reader%' OR ParentImage LIKE '%Microsoft Office%' OR ParentImage LIKE '%PDF Reader%') AND (Image="*\\brave.exe" OR Image="*\\chrome.exe" OR Image="*\\firefox.exe" OR Image="*\\msedge.exe" OR Image="*\\opera.exe" OR Image="*\\maxthon.exe" OR Image="*\\seamonkey.exe" OR Image="*\\vivaldi.exe") AND CommandLine LIKE '%http%') AND NOT ((CommandLine LIKE '%https://go.microsoft.com/fwlink/%')) AND NOT (((CommandLine LIKE '%http://ad.foxitsoftware.com/adlog.php?%' OR CommandLine LIKE '%https://globe-map.foxitservice.com/go.php?do=redirect%'))))
