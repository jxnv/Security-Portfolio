// Title: Potential Persistence Via Event Viewer Events.asp
// ID: a1e11042-a74a-46e6-b07c-c4ce8ecc239b
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-17
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects potential registry persistence technique using the Event Viewer "Events.asp" technique
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer\\MicrosoftRedirectionProgram" or TargetObject contains "\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer\\MicrosoftRedirectionURL")) and not (((Details = "(Empty)") or (action_process_image_path endswith "C:\\WINDOWS\\system32\\svchost.exe" and TargetObject endswith "\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer\\MicrosoftRedirectionProgram" and Details = "%%SystemRoot%%\\PCHealth\\HelpCtr\\Binaries\\HelpCtr.exe") or (action_process_image_path endswith "C:\\WINDOWS\\system32\\svchost.exe" and TargetObject endswith "\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer\\MicrosoftRedirectionProgramCommandLineParameters" and Details = "-url hcp://services/centers/support?topic=%%s") or (Details = "http://go.microsoft.com/fwlink/events.asp"))))
