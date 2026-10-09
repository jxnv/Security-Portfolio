// Title: Potential Fake Instance Of Hxtsr.EXE Executed
// ID: 4e762605-34a8-406d-b72e-c1a089313320
// Status: test
// Level: medium
// Author: Sreeman
// Date: 2020-04-17
// Tags: attack.stealth, attack.t1036
// Description: HxTsr.exe is a Microsoft compressed executable file called Microsoft Outlook Communications.
// HxTsr.exe is part of Outlook apps, because it resides in a hidden "WindowsApps" subfolder of "C:\Program Files".
// Any instances of hxtsr.exe not in this folder may be malware camouflaging itself as HxTsr.exe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\hxtsr.exe") and not ((action_process_image_path contains ":\\program files\\windowsapps\\microsoft.windowscommunicationsapps_" and action_process_image_path endswith "\\hxtsr.exe")))
