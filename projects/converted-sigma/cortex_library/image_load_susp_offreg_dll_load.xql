// Title: Potentially Suspicious Image Load of Offreg.dll
// ID: c9e5f013-4a6f-4d8c-9b0e-f7a4c3d26e95
// Status: experimental
// Level: medium
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-07-23
// Tags: attack.defense-impairment, attack.persistence, attack.t1112
// Description: Detects potentially suspicious loading of the Offline Registry Library (offreg.dll).
// Offreg.dll enables direct read/write access to offline registry hives without invoking the Windows Registry API,
// bypassing its associated audit logging and telemetry. Attackers may abuse this to stealthily modify registry hives
// while evading detection mechanisms that rely on standard registry event logs.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ImageLoaded endswith "\\offreg.dll") and not (((action_process_image_path startswith "C:\\Users\\" and action_process_image_path contains "\\AppData\\Local\\Programs\\") or (action_process_image_path startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\" and action_process_image_path endswith "\\MsMpEng.exe") or ((action_process_image_path startswith "C:\\Program Files\\" or action_process_image_path startswith "C:\\Program Files (x86)\\")) or ((action_process_image_path startswith "C:\\Windows\\System32\\" or action_process_image_path startswith "C:\\Windows\\SysWOW64\\" or action_process_image_path startswith "C:\\Windows\\WinSxS\\")))))
