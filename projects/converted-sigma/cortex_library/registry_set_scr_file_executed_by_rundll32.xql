// Title: ScreenSaver Registry Key Set
// ID: 40b6e656-4e11-4c0c-8772-c1cc6dae34ce
// Status: test
// Level: medium
// Author: Jose Luis Sanchez Martinez (@Joseliyo_Jstnk)
// Date: 2022-05-04
// Tags: attack.stealth, attack.t1218.011
// Description: Detects registry key established after masqueraded .scr file execution using Rundll32 through desk.cpl
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\rundll32.exe") and (TargetObject contains "\\Control Panel\\Desktop\\SCRNSAVE.EXE" and Details endswith ".scr") and not (((Details contains "C:\\Windows\\System32\\" or Details contains "C:\\Windows\\SysWOW64\\"))))
