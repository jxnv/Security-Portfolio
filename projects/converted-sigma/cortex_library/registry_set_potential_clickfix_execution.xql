// Title: Potential ClickFix Execution Pattern - Registry
// ID: f5fe36cf-f1ec-4c23-903d-09a3110f6bbb
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-03-25
// Tags: attack.execution, attack.t1204.001
// Description: Detects potential ClickFix malware execution patterns by monitoring registry modifications in RunMRU keys containing HTTP/HTTPS links.
// ClickFix is known to be distributed through phishing campaigns and uses techniques like clipboard hijacking and fake CAPTCHA pages.
// Through the fakecaptcha pages, the adversary tricks users into opening the Run dialog box and pasting clipboard-hijacked content,
// such as one-liners that execute remotely hosted malicious files or scripts.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((Details contains "http://" or Details contains "https://")) and (TargetObject contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\") and (((Details contains "account" or Details contains "anti-bot" or Details contains "botcheck" or Details contains "captcha" or Details contains "challenge" or Details contains "confirmation" or Details contains "fraud" or Details contains "human" or Details contains "identification" or Details contains "identificator" or Details contains "identity" or Details contains "robot" or Details contains "validation" or Details contains "verification" or Details contains "verify")) or ((Details contains "%comspec%" or Details contains "bitsadmin" or Details contains "certutil" or Details contains "cmd" or Details contains "cscript" or Details contains "curl" or Details contains "finger" or Details contains "mshta" or Details contains "powershell" or Details contains "pwsh" or Details contains "regsvr32" or Details contains "rundll32" or Details contains "schtasks" or Details contains "wget" or Details contains "wscript"))))
