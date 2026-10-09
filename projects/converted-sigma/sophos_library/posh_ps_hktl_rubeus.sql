-- Title: HackTool - Rubeus Execution - ScriptBlock
-- ID: 3245cd30-e015-40ff-a31d-5cadd5f377ec
-- Status: test
-- Level: high
-- Author: Christian Burkard (Nextron Systems), Florian Roth (Nextron Systems)
-- Date: 2023-04-27
-- Tags: attack.credential-access, attack.t1003, attack.t1558.003, attack.lateral-movement, attack.t1550.003
-- Description: Detects the execution of the hacktool Rubeus using specific command line flags
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ScriptBlockText ILIKE '%asreproast %' OR ScriptBlockText ILIKE '%dump /service:krbtgt %' OR ScriptBlockText ILIKE '%dump /luid:0x%' OR ScriptBlockText ILIKE '%kerberoast %' OR ScriptBlockText ILIKE '%createnetonly /program:%' OR ScriptBlockText ILIKE '%ptt /ticket:%' OR ScriptBlockText ILIKE '%/impersonateuser:%' OR ScriptBlockText ILIKE '%renew /ticket:%' OR ScriptBlockText ILIKE '%asktgt /user:%' OR ScriptBlockText ILIKE '%harvest /interval:%' OR ScriptBlockText ILIKE '%s4u /user:%' OR ScriptBlockText ILIKE '%s4u /ticket:%' OR ScriptBlockText ILIKE '%hash /password:%' OR ScriptBlockText ILIKE '%golden /aes256:%' OR ScriptBlockText ILIKE '%silver /user:%'))
