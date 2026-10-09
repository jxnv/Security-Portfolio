// Title: Suspicious Reconnaissance Activity Using Get-LocalGroupMember Cmdlet
// ID: c8a180d6-47a3-4345-a609-53f9c3d834fc
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-10
// Tags: attack.discovery, attack.t1087.001
// Description: Detects suspicious reconnaissance command line activity on Windows systems using the PowerShell Get-LocalGroupMember Cmdlet
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine contains "Get-LocalGroupMember ") AND ((CommandLine contains "domain admins" OR CommandLine contains " administrator" OR CommandLine contains " administrateur" OR CommandLine contains "enterprise admins" OR CommandLine contains "Exchange Trusted Subsystem" OR CommandLine contains "Remote Desktop Users" OR CommandLine contains "Utilisateurs du Bureau à distance" OR CommandLine contains "Usuarios de escritorio remoto")))
