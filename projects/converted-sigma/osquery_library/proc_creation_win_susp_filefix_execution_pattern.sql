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

SELECT * FROM processes WHERE (((ParentImage="*\\brave.exe" OR ParentImage="*\\chrome.exe" OR ParentImage="*\\firefox.exe" OR ParentImage="*\\msedge.exe") AND CommandLine LIKE '%#%') AND (((CommandLine LIKE '%account%' OR CommandLine LIKE '%anti-bot%' OR CommandLine LIKE '%botcheck%' OR CommandLine LIKE '%captcha%' OR CommandLine LIKE '%challenge%' OR CommandLine LIKE '%confirmation%' OR CommandLine LIKE '%fraud%' OR CommandLine LIKE '%human%' OR CommandLine LIKE '%identification%' OR CommandLine LIKE '%identificator%' OR CommandLine LIKE '%identity%' OR CommandLine LIKE '%robot%' OR CommandLine LIKE '%validation%' OR CommandLine LIKE '%verification%' OR CommandLine LIKE '%verify%')) OR ((CommandLine LIKE '%%comspec%%' OR CommandLine LIKE '%bitsadmin%' OR CommandLine LIKE '%certutil%' OR CommandLine LIKE '%cmd%' OR CommandLine LIKE '%cscript%' OR CommandLine LIKE '%curl%' OR CommandLine LIKE '%finger%' OR CommandLine LIKE '%mshta%' OR CommandLine LIKE '%powershell%' OR CommandLine LIKE '%pwsh%' OR CommandLine LIKE '%regsvr32%' OR CommandLine LIKE '%rundll32%' OR CommandLine LIKE '%schtasks%' OR CommandLine LIKE '%wget%' OR CommandLine LIKE '%wscript%'))))
