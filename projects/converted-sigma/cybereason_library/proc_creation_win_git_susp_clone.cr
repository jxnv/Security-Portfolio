// Title: Suspicious Git Clone
// ID: aef9d1f1-7396-4e92-a927-4567c7a495c1
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-03
// Tags: attack.reconnaissance, attack.t1593.003
// Description: Detects execution of "git" in order to clone a remote repository that contain suspicious keywords which might be suspicious
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains " clone " OR CommandLine contains "git-remote-https ")) AND (((Image="*\\git.exe" OR Image="*\\git-remote-https.exe")) OR (OriginalFileName == "git.exe")) AND ((CommandLine contains "exploit" OR CommandLine contains "Vulns" OR CommandLine contains "vulnerability" OR CommandLine contains "RemoteCodeExecution" OR CommandLine contains "Invoke-" OR CommandLine contains "CVE-" OR CommandLine contains "poc-" OR CommandLine contains "ProofOfConcept" OR CommandLine contains "proxyshell" OR CommandLine contains "log4shell" OR CommandLine contains "eternalblue" OR CommandLine contains "eternal-blue" OR CommandLine contains "MS17-")))
