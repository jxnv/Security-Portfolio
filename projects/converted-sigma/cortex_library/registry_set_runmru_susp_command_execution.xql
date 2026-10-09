// Title: Potentially Suspicious Command Executed Via Run Dialog Box - Registry
// ID: a7df0e9e-91a5-459a-a003-4cde67c2ff5d
// Status: test
// Level: high
// Author: Ahmed Farouk, Nasreddine Bencherchali
// Date: 2024-11-01
// Tags: attack.execution, attack.t1059.001
// Description: Detects execution of commands via the run dialog box on Windows by checking values of the "RunMRU" registry key.
// This technique was seen being abused by threat actors to deceive users into pasting and executing malicious commands, often disguised as CAPTCHA verification steps.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU") and ((((Details contains "powershell" or Details contains "pwsh")) and ((Details contains " -e " or Details contains " -ec " or Details contains " -en " or Details contains " -enc " or Details contains " -enco" or Details contains "ftp" or Details contains "Hidden" or Details contains "http" or Details contains "iex" or Details contains "Invoke-"))) or ((Details contains "wmic") and ((Details contains "shadowcopy" or Details contains "process call create")))))
