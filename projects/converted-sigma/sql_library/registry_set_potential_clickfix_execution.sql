-- Title: Potential ClickFix Execution Pattern - Registry
-- ID: f5fe36cf-f1ec-4c23-903d-09a3110f6bbb
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-03-25
-- Tags: attack.execution, attack.t1204.001
-- Description: Detects potential ClickFix malware execution patterns by monitoring registry modifications in RunMRU keys containing HTTP/HTTPS links.
-- ClickFix is known to be distributed through phishing campaigns and uses techniques like clipboard hijacking and fake CAPTCHA pages.
-- Through the fakecaptcha pages, the adversary tricks users into opening the Run dialog box and pasting clipboard-hijacked content,
-- such as one-liners that execute remotely hosted malicious files or scripts.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Details ILIKE '%http://%' OR Details ILIKE '%https://%')) AND (TargetObject ILIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\%') AND (((Details ILIKE '%account%' OR Details ILIKE '%anti-bot%' OR Details ILIKE '%botcheck%' OR Details ILIKE '%captcha%' OR Details ILIKE '%challenge%' OR Details ILIKE '%confirmation%' OR Details ILIKE '%fraud%' OR Details ILIKE '%human%' OR Details ILIKE '%identification%' OR Details ILIKE '%identificator%' OR Details ILIKE '%identity%' OR Details ILIKE '%robot%' OR Details ILIKE '%validation%' OR Details ILIKE '%verification%' OR Details ILIKE '%verify%')) OR ((Details ILIKE '%%comspec%%' OR Details ILIKE '%bitsadmin%' OR Details ILIKE '%certutil%' OR Details ILIKE '%cmd%' OR Details ILIKE '%cscript%' OR Details ILIKE '%curl%' OR Details ILIKE '%finger%' OR Details ILIKE '%mshta%' OR Details ILIKE '%powershell%' OR Details ILIKE '%pwsh%' OR Details ILIKE '%regsvr32%' OR Details ILIKE '%rundll32%' OR Details ILIKE '%schtasks%' OR Details ILIKE '%wget%' OR Details ILIKE '%wscript%'))))
