// Title: FileFix - Command Evidence in TypedPaths
// ID: 4fee3d51-8069-4a4c-a0f7-924fcaff2c70
// Status: experimental
// Level: high
// Author: Alfie Champion (delivr.to), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-07-05
// Tags: attack.execution, attack.t1204.004
// Description: Detects commonly-used chained commands and strings in the most recent 'url' value of the 'TypedPaths' key, which could be indicative of a user being targeted by the FileFix technique.
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths\\url1" AND (Details contains "#" AND Details contains "http")) AND (((Details contains "account" OR Details contains "anti-bot" OR Details contains "botcheck" OR Details contains "captcha" OR Details contains "challenge" OR Details contains "confirmation" OR Details contains "fraud" OR Details contains "human" OR Details contains "identification" OR Details contains "identificator" OR Details contains "identity" OR Details contains "robot" OR Details contains "validation" OR Details contains "verification" OR Details contains "verify")) OR ((Details contains "%comspec%" OR Details contains "bitsadmin" OR Details contains "certutil" OR Details contains "cmd" OR Details contains "cscript" OR Details contains "curl" OR Details contains "finger" OR Details contains "mshta" OR Details contains "powershell" OR Details contains "pwsh" OR Details contains "regsvr32" OR Details contains "rundll32" OR Details contains "schtasks" OR Details contains "wget" OR Details contains "wscript"))))
