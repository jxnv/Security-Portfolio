// Title: Potential Mpclient.DLL Sideloading
// ID: 418dc89a-9808-4b87-b1d7-e5ae0cb6effc
// Status: test
// Level: high
// Author: Bhabesh Raj
// Date: 2022-08-02
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects potential sideloading of "mpclient.dll" by Windows Defender processes ("MpCmdRun" and "NisSrv") from their non-default directory.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ImageLoaded endswith "\\mpclient.dll" and (action_process_image_path endswith "\\MpCmdRun.exe" or action_process_image_path endswith "\\NisSrv.exe")) and not (((action_process_image_path startswith "C:\\Program Files (x86)\\Windows Defender\\" or action_process_image_path startswith "C:\\Program Files\\Microsoft Security Client\\" or action_process_image_path startswith "C:\\Program Files\\Windows Defender\\" or action_process_image_path startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\" or action_process_image_path startswith "C:\\Windows\\WinSxS\\"))))
