// Title: Security Support Provider (SSP) Added to LSA Configuration
// ID: eeb30123-9fbd-4ee8-aaa0-2e545bbed6dc
// Status: test
// Level: high
// Author: iwillkeepwatch
// Date: 2019-01-18
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.005
// Description: Detects the addition of a SSP to the registry. Upon a reboot or API call, SSP DLLs gain access to encrypted and plaintext passwords stored in Windows.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject endswith "\\Control\\Lsa\\Security Packages" or TargetObject endswith "\\Control\\Lsa\\OSConfig\\Security Packages")) and not (((action_process_image_path = null) or ((action_process_image_path = "C:\\Windows\\system32\\msiexec.exe" or action_process_image_path = "C:\\Windows\\syswow64\\MsiExec.exe")))))
