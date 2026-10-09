// Title: Potential Mpclient.DLL Sideloading Via Defender Binaries
// ID: 7002aa10-b8d4-47ae-b5ba-51ab07e228b9
// Status: test
// Level: high
// Author: Bhabesh Raj
// Date: 2022-08-01
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects potential sideloading of "mpclient.dll" by Windows Defender processes ("MpCmdRun" and "NisSrv") from their non-default directory.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\MpCmdRun.exe" or action_process_image_path endswith "\\NisSrv.exe")) and not (((action_process_image_path startswith "C:\\Program Files (x86)\\Windows Defender\\" or action_process_image_path startswith "C:\\Program Files\\Microsoft Security Client\\" or action_process_image_path startswith "C:\\Program Files\\Windows Defender\\" or action_process_image_path startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\" or action_process_image_path startswith "C:\\Windows\\WinSxS\\"))))
