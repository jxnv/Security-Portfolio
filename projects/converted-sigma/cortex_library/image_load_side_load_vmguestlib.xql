// Title: VMGuestLib DLL Sideload
// ID: 70e8e9b4-6a93-4cb7-8cde-da69502e7aff
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-01
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects DLL sideloading of VMGuestLib.dll by the WmiApSrv service.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ImageLoaded contains "\\VMware\\VMware Tools\\vmStatsProvider\\win32" and ImageLoaded contains "\\vmGuestLib.dll") and action_process_image_path endswith "\\Windows\\System32\\wbem\\WmiApSrv.exe") and not ((Signed = "true")))
