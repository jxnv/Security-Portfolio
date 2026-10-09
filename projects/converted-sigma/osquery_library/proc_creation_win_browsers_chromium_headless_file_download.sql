-- Title: File Download with Headless Browser
-- ID: 0e8cfe08-02c9-4815-a2f8-0d157b7ed33e
-- Status: test
-- Level: high
-- Author: Sreeman, Florian Roth (Nextron Systems)
-- Date: 2022-01-04
-- Tags: attack.command-and-control, attack.stealth, attack.t1105, attack.t1564.003
-- Description: Detects execution of chromium based browser in headless mode using the "dump-dom" command line to download files
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\brave.exe" OR Image="*\\chrome.exe" OR Image="*\\msedge.exe" OR Image="*\\opera.exe" OR Image="*\\vivaldi.exe") AND (CommandLine LIKE '%--headless%' AND CommandLine LIKE '%dump-dom%' AND CommandLine LIKE '%http%')) AND NOT ((((Image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\*" OR Image="C:\\Program Files (x86)\\Microsoft\\EdgeCore\\*" OR Image="C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\*" OR Image="C:\\Program Files\\Microsoft\\Edge\\Application\\*" OR Image="C:\\Program Files\\Microsoft\\EdgeCore\\*" OR Image="C:\\Program Files\\Microsoft\\EdgeWebView\\*" OR Image="C:\\Program Files\\WindowsApps\\Microsoft.MicrosoftEdge*") AND (Image="*\\msedge.exe" OR Image="*\\msedgewebview2.exe" OR Image="*\\MicrosoftEdge.exe") AND CommandLine LIKE '%--headless --disable-gpu --disable-extensions --disable-plugins --mute-audio --no-first-run --incognito --aggressive-cache-discard --dump-dom%') OR ((Image LIKE '%\\AppData\\Local\\Microsoft\\WindowsApps\\%' OR Image LIKE '%\\Windows\\SystemApps\\Microsoft.MicrosoftEdge%') AND (Image="*\\msedge.exe" OR Image="*\\MicrosoftEdge.exe") AND CommandLine LIKE '%--headless --disable-gpu --disable-extensions --disable-plugins --mute-audio --no-first-run --incognito --aggressive-cache-discard --dump-dom%'))))
