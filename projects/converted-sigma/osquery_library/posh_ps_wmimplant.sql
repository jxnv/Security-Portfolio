-- Title: WMImplant Hack Tool
-- ID: 8028c2c3-e25a-46e3-827f-bbb5abf181d7
-- Status: test
-- Level: high
-- Author: NVISO
-- Date: 2020-03-26
-- Tags: attack.execution, attack.t1047, attack.t1059.001
-- Description: Detects parameters used by WMImplant
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((ScriptBlockText LIKE '%WMImplant%' OR ScriptBlockText LIKE '% change_user %' OR ScriptBlockText LIKE '% gen_cli %' OR ScriptBlockText LIKE '% command_exec %' OR ScriptBlockText LIKE '% disable_wdigest %' OR ScriptBlockText LIKE '% disable_winrm %' OR ScriptBlockText LIKE '% enable_wdigest %' OR ScriptBlockText LIKE '% enable_winrm %' OR ScriptBlockText LIKE '% registry_mod %' OR ScriptBlockText LIKE '% remote_posh %' OR ScriptBlockText LIKE '% sched_job %' OR ScriptBlockText LIKE '% service_mod %' OR ScriptBlockText LIKE '% process_kill %' OR ScriptBlockText LIKE '% active_users %' OR ScriptBlockText LIKE '% basic_info %' OR ScriptBlockText LIKE '% power_off %' OR ScriptBlockText LIKE '% vacant_system %' OR ScriptBlockText LIKE '% logon_events %'))
