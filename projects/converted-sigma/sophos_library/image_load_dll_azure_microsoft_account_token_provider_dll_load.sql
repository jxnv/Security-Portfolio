-- Title: Potential Azure Browser SSO Abuse
-- ID: 50f852e6-af22-4c78-9ede-42ef36aa3453
-- Status: test
-- Level: low
-- Author: Den Iuzvyk
-- Date: 2020-07-15
-- Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects abusing Azure Browser SSO by requesting OAuth 2.0 refresh tokens for an Azure-AD-authenticated Windows user (i.e. the machine is joined to Azure AD and a user logs in with their Azure AD account) wanting to perform SSO authentication in the browser.
-- An attacker can use this to authenticate to Azure AD in a browser as that user.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ImageLoaded = 'C:\\Windows\\System32\\MicrosoftAccountTokenProvider.dll') AND NOT (((Image ILIKE 'C:\\Windows\\System32\\%' OR Image ILIKE 'C:\\Windows\\SysWOW64\\%') AND Image ILIKE '%\\BackgroundTaskHost.exe')) AND NOT ((((Image ILIKE 'C:\\Program Files\\Microsoft Visual Studio\\%' OR Image ILIKE 'C:\\Program Files (x86)\\Microsoft Visual Studio\\%') AND Image ILIKE '%\\IDE\\devenv.exe') OR ((Image ILIKE 'C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\%') OR (Image ILIKE '%\\WindowsApps\\MicrosoftEdge.exe') OR ((Image = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe' OR Image = 'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe'))) OR ((Image ILIKE 'C:\\Program Files (x86)\\Microsoft\\EdgeCore\\%' OR Image ILIKE 'C:\\Program Files\\Microsoft\\EdgeCore\\%') AND (Image ILIKE '%\\msedge.exe' OR Image ILIKE '%\\msedgewebview2.exe')) OR ((Image = 'C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe' OR Image = 'C:\\Program Files\\Internet Explorer\\iexplore.exe')) OR (Image IS NULL) OR (Image ILIKE '%\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe'))))
