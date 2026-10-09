-- Title: WMImplant Hack Tool
-- ID: 8028c2c3-e25a-46e3-827f-bbb5abf181d7
-- Status: test
-- Level: high
-- Author: NVISO
-- Date: 2020-03-26
-- Tags: attack.execution, attack.t1047, attack.t1059.001
-- Description: Detects parameters used by WMImplant
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ScriptBlockText ILIKE '%WMImplant%' OR ScriptBlockText ILIKE '% change_user %' OR ScriptBlockText ILIKE '% gen_cli %' OR ScriptBlockText ILIKE '% command_exec %' OR ScriptBlockText ILIKE '% disable_wdigest %' OR ScriptBlockText ILIKE '% disable_winrm %' OR ScriptBlockText ILIKE '% enable_wdigest %' OR ScriptBlockText ILIKE '% enable_winrm %' OR ScriptBlockText ILIKE '% registry_mod %' OR ScriptBlockText ILIKE '% remote_posh %' OR ScriptBlockText ILIKE '% sched_job %' OR ScriptBlockText ILIKE '% service_mod %' OR ScriptBlockText ILIKE '% process_kill %' OR ScriptBlockText ILIKE '% active_users %' OR ScriptBlockText ILIKE '% basic_info %' OR ScriptBlockText ILIKE '% power_off %' OR ScriptBlockText ILIKE '% vacant_system %' OR ScriptBlockText ILIKE '% logon_events %'))
