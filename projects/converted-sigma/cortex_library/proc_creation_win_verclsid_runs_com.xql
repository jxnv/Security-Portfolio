// Title: Verclsid.exe Runs COM Object
// ID: d06be4b9-8045-428b-a567-740a26d9db25
// Status: test
// Level: medium
// Author: Victor Sergeev, oscd.community
// Date: 2020-10-09
// Tags: attack.stealth, attack.t1218
// Description: Detects when verclsid.exe is used to run COM object via GUID
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "/S" and action_process_image_command_line contains "/C")) and ((action_process_image_path endswith "\\verclsid.exe") or (action_process_image_name = "verclsid.exe"))) and not ((actor_process_image_path endswith "C:\\Windows\\System32\\RuntimeBroker.exe" and (action_process_image_command_line contains "verclsid.exe\" /S /C {" and action_process_image_command_line contains "} /I {"))))
