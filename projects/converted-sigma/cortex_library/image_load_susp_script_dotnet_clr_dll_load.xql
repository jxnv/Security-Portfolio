// Title: DotNet CLR DLL Loaded By Scripting Applications
// ID: 4508a70e-97ef-4300-b62b-ff27992990ea
// Status: test
// Level: high
// Author: omkar72, oscd.community
// Date: 2020-10-14
// Tags: attack.execution, attack.privilege-escalation, attack.stealth, attack.t1055
// Description: Detects .NET CLR DLLs being loaded by scripting applications such as wscript or cscript. This could be an indication of potential suspicious execution.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\cmstp.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\msxsl.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\wmic.exe" or action_process_image_path endswith "\\wscript.exe") and (ImageLoaded endswith "\\clr.dll" or ImageLoaded endswith "\\mscoree.dll" or ImageLoaded endswith "\\mscorlib.dll"))
