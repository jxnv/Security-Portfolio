// Title: SCR File Write Event
// ID: c048f047-7e2a-4888-b302-55f509d4a91d
// Status: test
// Level: medium
// Author: Christopher Peacock @securepeacock, SCYTHE @scythe_io
// Date: 2022-04-27
// Tags: attack.stealth, attack.t1218.011
// Description: Detects the creation of screensaver files (.scr) outside of system folders. Attackers may execute an application as an ".SCR" file using "rundll32.exe desk.cpl,InstallScreenSaver" for example.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path endswith ".scr") and not (((action_file_path contains ":\\$WINDOWS.~BT\\NewOS\\" or action_file_path contains ":\\Windows\\System32\\" or action_file_path contains ":\\Windows\\SysWOW64\\" or action_file_path contains ":\\Windows\\WinSxS\\" or action_file_path contains ":\\WUDownloadCache\\"))))
