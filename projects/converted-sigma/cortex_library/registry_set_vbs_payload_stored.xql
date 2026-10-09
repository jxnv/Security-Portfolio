// Title: VBScript Payload Stored in Registry
// ID: 46490193-1b22-4c29-bdd6-5bf63907216f
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-03-05
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
// Description: Detects VBScript content stored into registry keys as seen being used by UNC2452 group
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "Software\\Microsoft\\Windows\\CurrentVersion" and (Details contains "vbscript:" or Details contains "jscript:" or Details contains "mshtml," or Details contains "RunHTMLApplication" or Details contains "Execute(" or Details contains "CreateObject" or Details contains "window.close")) and not (((TargetObject contains "Software\\Microsoft\\Windows\\CurrentVersion\\Run") or (action_process_image_path endswith "\\msiexec.exe" and TargetObject contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\" and (Details contains "\\Microsoft.NET\\Primary Interop Assemblies\\Microsoft.mshtml.dll" or Details contains "<\\Microsoft.mshtml,fileVersion=" or Details contains "_mshtml_dll_" or Details contains "<\\Microsoft.mshtml,culture=")))))
