// Title: Aruba Network Service Potential DLL Sideloading
// ID: 90ae0469-0cee-4509-b67f-e5efcef040f7
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-22
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects potential DLL sideloading activity via the Aruba Networks Virtual Intranet Access "arubanetsvc.exe" process using DLL Search Order Hijacking
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\arubanetsvc.exe" and (ImageLoaded endswith "\\wtsapi32.dll" or ImageLoaded endswith "\\msvcr100.dll" or ImageLoaded endswith "\\msvcp100.dll" or ImageLoaded endswith "\\dbghelp.dll" or ImageLoaded endswith "\\dbgcore.dll" or ImageLoaded endswith "\\wininet.dll" or ImageLoaded endswith "\\iphlpapi.dll" or ImageLoaded endswith "\\version.dll" or ImageLoaded endswith "\\cryptsp.dll" or ImageLoaded endswith "\\cryptbase.dll" or ImageLoaded endswith "\\wldp.dll" or ImageLoaded endswith "\\profapi.dll" or ImageLoaded endswith "\\sspicli.dll" or ImageLoaded endswith "\\winsta.dll" or ImageLoaded endswith "\\dpapi.dll")) and not (((ImageLoaded startswith "C:\\Windows\\System32\\" or ImageLoaded startswith "C:\\Windows\\SysWOW64\\" or ImageLoaded startswith "C:\\Windows\\WinSxS\\"))))
