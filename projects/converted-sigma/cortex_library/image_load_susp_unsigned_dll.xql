// Title: Unsigned DLL Loaded by Windows Utility
// ID: b5de0c9a-6f19-43e0-af4e-55ad01f550af
// Status: test
// Level: medium
// Author: Swachchhanda Shrawan Poudel
// Date: 2024-02-28
// Tags: attack.stealth, attack.t1218.011, attack.t1218.010
// Description: Detects windows utilities loading an unsigned or untrusted DLL.
// Adversaries often abuse those programs to proxy execution of malicious code.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\InstallUtil.exe" or action_process_image_path endswith "\\RegAsm.exe" or action_process_image_path endswith "\\RegSvcs.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe")) and not ((((action_process_image_path startswith "C:\\Windows\\SysWOW64\\" or action_process_image_path startswith "C:\\Windows\\System32\\" or action_process_image_path startswith "C:\\Windows\\Microsoft.NET\\Framework64") and action_process_image_path endswith "\\RegAsm.exe" and ImageLoaded endswith ".dll" and ImageLoaded startswith "C:\\Windows\\assembly\\NativeImages") or ((SignatureStatus = "errorChaining" or SignatureStatus = "errorCode_endpoint" or SignatureStatus = "errorExpired" or SignatureStatus = "trusted" or SignatureStatus = "Valid")) or ((SignatureStatus = "" or SignatureStatus = "-")) or (SignatureStatus = null) or (Signed = "true") or ((Signed = "" or Signed = "-")) or (Signed = null) or ((action_process_image_path = "C:\\Windows\\SysWOW64\\rundll32.exe" or action_process_image_path = "C:\\Windows\\System32\\rundll32.exe") and ImageLoaded startswith "C:\\Windows\\Installer\\" and (ImageLoaded endswith ".tmp-\\Microsoft.Deployment.WindowsInstaller.dll" or ImageLoaded endswith ".tmp-\\Avira.OE.Setup.CustomActions.dll")))) and not (((action_process_image_path = "C:\\Windows\\SysWOW64\\regsvr32.exe" or action_process_image_path = "C:\\Windows\\System32\\regsvr32.exe") and (ImageLoaded startswith "C:\\Program Files (x86)\\K-Lite Codec Pack\\" or ImageLoaded startswith "C:\\Program Files\\K-Lite Codec Pack\\"))))
