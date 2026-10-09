// Title: WMImplant Hack Tool
// ID: 8028c2c3-e25a-46e3-827f-bbb5abf181d7
// Status: test
// Level: high
// Author: NVISO
// Date: 2020-03-26
// Tags: attack.execution, attack.t1047, attack.t1059.001
// Description: Detects parameters used by WMImplant
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ScriptBlockText contains "WMImplant" or ScriptBlockText contains " change_user " or ScriptBlockText contains " gen_cli " or ScriptBlockText contains " command_exec " or ScriptBlockText contains " disable_wdigest " or ScriptBlockText contains " disable_winrm " or ScriptBlockText contains " enable_wdigest " or ScriptBlockText contains " enable_winrm " or ScriptBlockText contains " registry_mod " or ScriptBlockText contains " remote_posh " or ScriptBlockText contains " sched_job " or ScriptBlockText contains " service_mod " or ScriptBlockText contains " process_kill " or ScriptBlockText contains " active_users " or ScriptBlockText contains " basic_info " or ScriptBlockText contains " power_off " or ScriptBlockText contains " vacant_system " or ScriptBlockText contains " logon_events "))
