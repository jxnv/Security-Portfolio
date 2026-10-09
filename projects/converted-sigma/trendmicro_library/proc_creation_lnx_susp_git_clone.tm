// Title: Suspicious Git Clone - Linux
// ID: cfec9d29-64ec-4a0f-9ffe-0fdb856d5446
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-03
// Tags: attack.reconnaissance, attack.t1593.003
// Description: Detects execution of "git" in order to clone a remote repository that contain suspicious keywords which might be suspicious
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*/git" AND CommandLine: "* clone *") AND ((CommandLine: "*exploit*" OR CommandLine: "*Vulns*" OR CommandLine: "*vulnerability*" OR CommandLine: "*RCE*" OR CommandLine: "*RemoteCodeExecution*" OR CommandLine: "*Invoke-*" OR CommandLine: "*CVE-*" OR CommandLine: "*poc-*" OR CommandLine: "*ProofOfConcept*" OR CommandLine: "*proxyshell*" OR CommandLine: "*log4shell*" OR CommandLine: "*eternalblue*" OR CommandLine: "*eternal-blue*" OR CommandLine: "*MS17-*")))
