// Title: HackTool - SharpChisel Execution
// ID: cf93e05e-d798-4d9e-b522-b0248dc61eaf
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-05
// Tags: attack.command-and-control, attack.t1090.001
// Description: Detects usage of the Sharp Chisel via the commandline arguments
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\SharpChisel.exe") OR (Product == "SharpChisel"))
