// Title: Potential Adplus.EXE Abuse
// ID: 2f869d59-7f6a-4931-992c-cce556ff2d53
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-09
// Tags: attack.execution, attack.credential-access, attack.t1003.001
// Description: Detects execution of "AdPlus.exe", a binary that is part of the Windows SDK that can be used as a LOLBIN in order to dump process memory and execute arbitrary commands.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "* -hang *" OR CommandLine: "* -pn *" OR CommandLine: "* -pmn *" OR CommandLine: "* -p *" OR CommandLine: "* -po *" OR CommandLine: "* -c *" OR CommandLine: "* -sc *")) AND ((Image="*\\adplus.exe") OR (OriginalFileName: "Adplus.exe")))
