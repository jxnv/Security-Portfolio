-- Title: Suspicious FileFix Execution Pattern
-- ID: b5b29e4e-31fa-4fdf-b058-296e7a1aa0c2
-- Status: experimental
-- Level: high
-- Author: 0xFustang, Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-11-24
-- Tags: attack.execution, attack.t1204.004
-- Description: Detects suspicious FileFix execution patterns where users are tricked into running malicious commands through browser file upload dialog manipulation.
-- This attack typically begins when users visit malicious websites impersonating legitimate services or news platforms,
-- which may display fake CAPTCHA challenges or direct instructions to open file explorer and paste clipboard content.
-- The clipboard content usually contains commands that download and execute malware, such as information stealing tools.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((ParentImage ILIKE '%\\brave.exe' OR ParentImage ILIKE '%\\chrome.exe' OR ParentImage ILIKE '%\\firefox.exe' OR ParentImage ILIKE '%\\msedge.exe') AND CommandLine ILIKE '%#%') AND (((CommandLine ILIKE '%account%' OR CommandLine ILIKE '%anti-bot%' OR CommandLine ILIKE '%botcheck%' OR CommandLine ILIKE '%captcha%' OR CommandLine ILIKE '%challenge%' OR CommandLine ILIKE '%confirmation%' OR CommandLine ILIKE '%fraud%' OR CommandLine ILIKE '%human%' OR CommandLine ILIKE '%identification%' OR CommandLine ILIKE '%identificator%' OR CommandLine ILIKE '%identity%' OR CommandLine ILIKE '%robot%' OR CommandLine ILIKE '%validation%' OR CommandLine ILIKE '%verification%' OR CommandLine ILIKE '%verify%')) OR ((CommandLine ILIKE '%%comspec%%' OR CommandLine ILIKE '%bitsadmin%' OR CommandLine ILIKE '%certutil%' OR CommandLine ILIKE '%cmd%' OR CommandLine ILIKE '%cscript%' OR CommandLine ILIKE '%curl%' OR CommandLine ILIKE '%finger%' OR CommandLine ILIKE '%mshta%' OR CommandLine ILIKE '%powershell%' OR CommandLine ILIKE '%pwsh%' OR CommandLine ILIKE '%regsvr32%' OR CommandLine ILIKE '%rundll32%' OR CommandLine ILIKE '%schtasks%' OR CommandLine ILIKE '%wget%' OR CommandLine ILIKE '%wscript%'))))
