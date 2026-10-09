-- Title: File Download with Headless Browser
-- ID: 0e8cfe08-02c9-4815-a2f8-0d157b7ed33e
-- Status: test
-- Level: high
-- Author: Sreeman, Florian Roth (Nextron Systems)
-- Date: 2022-01-04
-- Tags: attack.command-and-control, attack.stealth, attack.t1105, attack.t1564.003
-- Description: Detects execution of chromium based browser in headless mode using the "dump-dom" command line to download files
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Image ILIKE '%\\brave.exe' OR Image ILIKE '%\\chrome.exe' OR Image ILIKE '%\\msedge.exe' OR Image ILIKE '%\\opera.exe' OR Image ILIKE '%\\vivaldi.exe') AND (CommandLine ILIKE '%--headless%' AND CommandLine ILIKE '%dump-dom%' AND CommandLine ILIKE '%http%')) AND NOT ((((Image ILIKE 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\%' OR Image ILIKE 'C:\\Program Files (x86)\\Microsoft\\EdgeCore\\%' OR Image ILIKE 'C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\%' OR Image ILIKE 'C:\\Program Files\\Microsoft\\Edge\\Application\\%' OR Image ILIKE 'C:\\Program Files\\Microsoft\\EdgeCore\\%' OR Image ILIKE 'C:\\Program Files\\Microsoft\\EdgeWebView\\%' OR Image ILIKE 'C:\\Program Files\\WindowsApps\\Microsoft.MicrosoftEdge%') AND (Image ILIKE '%\\msedge.exe' OR Image ILIKE '%\\msedgewebview2.exe' OR Image ILIKE '%\\MicrosoftEdge.exe') AND CommandLine ILIKE '%--headless --disable-gpu --disable-extensions --disable-plugins --mute-audio --no-first-run --incognito --aggressive-cache-discard --dump-dom%') OR ((Image ILIKE '%\\AppData\\Local\\Microsoft\\WindowsApps\\%' OR Image ILIKE '%\\Windows\\SystemApps\\Microsoft.MicrosoftEdge%') AND (Image ILIKE '%\\msedge.exe' OR Image ILIKE '%\\MicrosoftEdge.exe') AND CommandLine ILIKE '%--headless --disable-gpu --disable-extensions --disable-plugins --mute-audio --no-first-run --incognito --aggressive-cache-discard --dump-dom%'))))
