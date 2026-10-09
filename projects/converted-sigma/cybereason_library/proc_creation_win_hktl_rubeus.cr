// Title: HackTool - Rubeus Execution
// ID: 7ec2c172-dceb-4c10-92c9-87c1881b7e18
// Status: stable
// Level: critical
// Author: Florian Roth (Nextron Systems)
// Date: 2018-12-19
// Tags: attack.credential-access, attack.t1003, attack.t1558.003, attack.lateral-movement, attack.t1550.003
// Description: Detects the execution of the hacktool Rubeus via PE information of command line parameters
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\Rubeus.exe") OR (OriginalFileName == "Rubeus.exe") OR (Description == "Rubeus") OR ((CommandLine contains "asreproast " OR CommandLine contains "dump /service:krbtgt " OR CommandLine contains "dump /luid:0x" OR CommandLine contains "kerberoast " OR CommandLine contains "createnetonly /program:" OR CommandLine contains "ptt /ticket:" OR CommandLine contains "/impersonateuser:" OR CommandLine contains "renew /ticket:" OR CommandLine contains "asktgt /user:" OR CommandLine contains "harvest /interval:" OR CommandLine contains "s4u /user:" OR CommandLine contains "s4u /ticket:" OR CommandLine contains "hash /password:" OR CommandLine contains "golden /aes256:" OR CommandLine contains "silver /user:")))
