// Title: Potential DLL Sideloading Via VMware Xfer
// ID: 9313dc13-d04c-46d8-af4a-a930cc55d93b
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-02
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects loading of a DLL by the VMware Xfer utility from the non-default directory which may be an attempt to sideload arbitrary DLL
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\VMwareXferlogs.exe" and ImageLoaded endswith "\\glib-2.0.dll") and not ((ImageLoaded startswith "C:\\Program Files\\VMware\\")))
