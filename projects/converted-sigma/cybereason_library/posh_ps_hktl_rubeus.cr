// Title: HackTool - Rubeus Execution - ScriptBlock
// ID: 3245cd30-e015-40ff-a31d-5cadd5f377ec
// Status: test
// Level: high
// Author: Christian Burkard (Nextron Systems), Florian Roth (Nextron Systems)
// Date: 2023-04-27
// Tags: attack.credential-access, attack.t1003, attack.t1558.003, attack.lateral-movement, attack.t1550.003
// Description: Detects the execution of the hacktool Rubeus using specific command line flags
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText contains "asreproast " OR ScriptBlockText contains "dump /service:krbtgt " OR ScriptBlockText contains "dump /luid:0x" OR ScriptBlockText contains "kerberoast " OR ScriptBlockText contains "createnetonly /program:" OR ScriptBlockText contains "ptt /ticket:" OR ScriptBlockText contains "/impersonateuser:" OR ScriptBlockText contains "renew /ticket:" OR ScriptBlockText contains "asktgt /user:" OR ScriptBlockText contains "harvest /interval:" OR ScriptBlockText contains "s4u /user:" OR ScriptBlockText contains "s4u /ticket:" OR ScriptBlockText contains "hash /password:" OR ScriptBlockText contains "golden /aes256:" OR ScriptBlockText contains "silver /user:"))
