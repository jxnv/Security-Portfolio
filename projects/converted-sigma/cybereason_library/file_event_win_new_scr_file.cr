// Title: SCR File Write Event
// ID: c048f047-7e2a-4888-b302-55f509d4a91d
// Status: test
// Level: medium
// Author: Christopher Peacock @securepeacock, SCYTHE @scythe_io
// Date: 2022-04-27
// Tags: attack.stealth, attack.t1218.011
// Description: Detects the creation of screensaver files (.scr) outside of system folders. Attackers may execute an application as an ".SCR" file using "rundll32.exe desk.cpl,InstallScreenSaver" for example.
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetFilename="*.scr") AND NOT (((TargetFilename contains ":\\$WINDOWS.~BT\\NewOS\\" OR TargetFilename contains ":\\Windows\\System32\\" OR TargetFilename contains ":\\Windows\\SysWOW64\\" OR TargetFilename contains ":\\Windows\\WinSxS\\" OR TargetFilename contains ":\\WUDownloadCache\\"))))
