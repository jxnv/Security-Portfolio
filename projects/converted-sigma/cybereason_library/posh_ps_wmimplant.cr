// Title: WMImplant Hack Tool
// ID: 8028c2c3-e25a-46e3-827f-bbb5abf181d7
// Status: test
// Level: high
// Author: NVISO
// Date: 2020-03-26
// Tags: attack.execution, attack.t1047, attack.t1059.001
// Description: Detects parameters used by WMImplant
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText contains "WMImplant" OR ScriptBlockText contains " change_user " OR ScriptBlockText contains " gen_cli " OR ScriptBlockText contains " command_exec " OR ScriptBlockText contains " disable_wdigest " OR ScriptBlockText contains " disable_winrm " OR ScriptBlockText contains " enable_wdigest " OR ScriptBlockText contains " enable_winrm " OR ScriptBlockText contains " registry_mod " OR ScriptBlockText contains " remote_posh " OR ScriptBlockText contains " sched_job " OR ScriptBlockText contains " service_mod " OR ScriptBlockText contains " process_kill " OR ScriptBlockText contains " active_users " OR ScriptBlockText contains " basic_info " OR ScriptBlockText contains " power_off " OR ScriptBlockText contains " vacant_system " OR ScriptBlockText contains " logon_events "))
