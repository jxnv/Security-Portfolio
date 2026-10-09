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

SELECT * FROM file WHERE (((Details LIKE '%http://%' OR Details LIKE '%https://%')) AND (TargetObject LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\%') AND (((Details LIKE '%account%' OR Details LIKE '%anti-bot%' OR Details LIKE '%botcheck%' OR Details LIKE '%captcha%' OR Details LIKE '%challenge%' OR Details LIKE '%confirmation%' OR Details LIKE '%fraud%' OR Details LIKE '%human%' OR Details LIKE '%identification%' OR Details LIKE '%identificator%' OR Details LIKE '%identity%' OR Details LIKE '%robot%' OR Details LIKE '%validation%' OR Details LIKE '%verification%' OR Details LIKE '%verify%')) OR ((Details LIKE '%%comspec%%' OR Details LIKE '%bitsadmin%' OR Details LIKE '%certutil%' OR Details LIKE '%cmd%' OR Details LIKE '%cscript%' OR Details LIKE '%curl%' OR Details LIKE '%finger%' OR Details LIKE '%mshta%' OR Details LIKE '%powershell%' OR Details LIKE '%pwsh%' OR Details LIKE '%regsvr32%' OR Details LIKE '%rundll32%' OR Details LIKE '%schtasks%' OR Details LIKE '%wget%' OR Details LIKE '%wscript%'))))
