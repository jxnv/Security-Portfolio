// Title: FileFix - Command Evidence in TypedPaths
// ID: 4fee3d51-8069-4a4c-a0f7-924fcaff2c70
// Status: experimental
// Level: high
// Author: Alfie Champion (delivr.to), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-07-05
// Tags: attack.execution, attack.t1204.004
// Description: Detects commonly-used chained commands and strings in the most recent 'url' value of the 'TypedPaths' key, which could be indicative of a user being targeted by the FileFix technique.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject endswith "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths\\url1" and (Details contains "#" and Details contains "http")) and (((Details contains "account" or Details contains "anti-bot" or Details contains "botcheck" or Details contains "captcha" or Details contains "challenge" or Details contains "confirmation" or Details contains "fraud" or Details contains "human" or Details contains "identification" or Details contains "identificator" or Details contains "identity" or Details contains "robot" or Details contains "validation" or Details contains "verification" or Details contains "verify")) or ((Details contains "%comspec%" or Details contains "bitsadmin" or Details contains "certutil" or Details contains "cmd" or Details contains "cscript" or Details contains "curl" or Details contains "finger" or Details contains "mshta" or Details contains "powershell" or Details contains "pwsh" or Details contains "regsvr32" or Details contains "rundll32" or Details contains "schtasks" or Details contains "wget" or Details contains "wscript"))))
