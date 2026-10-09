// Title: Disable Administrative Share Creation at Startup
// ID: c7dcacd0-cc59-4004-b0a4-1d6cdebe6f3e
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-01-16
// Tags: attack.stealth, attack.t1070.005
// Description: Administrative shares are hidden network shares created by Microsoft Windows NT operating systems that grant system administrators remote access to every disk volume on a network-connected system
// Converted by: Sigma Universal SIEM/EDR CLI

(TargetObject: "*\\Services\\LanmanServer\\Parameters\\*" AND (TargetObject="*\\AutoShareWks" OR TargetObject="*\\AutoShareServer") AND Details: "DWORD (0x00000000)")
