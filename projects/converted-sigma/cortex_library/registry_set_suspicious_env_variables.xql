// Title: Suspicious Environment Variable Has Been Registered
// ID: 966315ef-c5e1-4767-ba25-fce9c8de3660
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-20
// Tags: attack.persistence, attack.stealth
// Description: Detects the creation of user-specific or system-wide environment variables via the registry. Which contains suspicious commands and strings
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((Details = "powershell" or Details = "pwsh")) or ((Details contains "\\AppData\\Local\\Temp\\" or Details contains "C:\\Users\\Public\\" or Details contains "TVqQAAMAAAAEAAAA" or Details contains "TVpQAAIAAAAEAA8A" or Details contains "TVqAAAEAAAAEABAA" or Details contains "TVoAAAAAAAAAAAAA" or Details contains "TVpTAQEAAAAEAAAA" or Details contains "SW52b2tlL" or Details contains "ludm9rZS" or Details contains "JbnZva2Ut" or Details contains "SQBuAHYAbwBrAGUALQ" or Details contains "kAbgB2AG8AawBlAC0A" or Details contains "JAG4AdgBvAGsAZQAtA")) or ((Details startswith "SUVY" or Details startswith "SQBFAF" or Details startswith "SQBuAH" or Details startswith "cwBhA" or Details startswith "aWV4" or Details startswith "aQBlA" or Details startswith "R2V0" or Details startswith "dmFy" or Details startswith "dgBhA" or Details startswith "dXNpbm" or Details startswith "H4sIA" or Details startswith "Y21k" or Details startswith "cABhAH" or Details startswith "Qzpc" or Details startswith "Yzpc"))) and (TargetObject contains "\\Environment\\"))
