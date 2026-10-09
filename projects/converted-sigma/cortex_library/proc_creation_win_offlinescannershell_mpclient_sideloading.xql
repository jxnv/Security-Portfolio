// Title: Potential Mpclient.DLL Sideloading Via OfflineScannerShell.EXE Execution
// ID: 02b18447-ea83-4b1b-8805-714a8a34546a
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-03-06
// Tags: attack.stealth, attack.t1218
// Description: Detects execution of Windows Defender "OfflineScannerShell.exe" from its non standard directory.
// The "OfflineScannerShell.exe" binary is vulnerable to DLL side loading and will load any DLL named "mpclient.dll" from the current working directory.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\OfflineScannerShell.exe") or (action_process_image_name = "OfflineScannerShell.exe")) and not (((CurrentDirectory = "") or (CurrentDirectory = "C:\\Program Files\\Windows Defender\\Offline\\") or (CurrentDirectory = null))))
