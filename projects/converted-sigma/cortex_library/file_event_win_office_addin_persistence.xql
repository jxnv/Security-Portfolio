// Title: Potential Persistence Via Microsoft Office Add-In
// ID: 8e1cb247-6cf6-42fa-b440-3f27d57e9936
// Status: test
// Level: high
// Author: NVISO
// Date: 2020-05-11
// Tags: attack.persistence, attack.t1137.006
// Description: Detects potential persistence activity via startup add-ins that load when Microsoft Office starts (.wll/.xll are simply .dll fit for Word or Excel).
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path contains "\\Microsoft\\Addins\\" and (action_file_path endswith ".xlam" or action_file_path endswith ".xla" or action_file_path endswith ".ppam")) or (action_file_path contains "\\Microsoft\\Word\\Startup\\" and action_file_path endswith ".wll") or (action_file_path contains "Microsoft\\Excel\\XLSTART\\" and action_file_path endswith ".xlam") or (action_file_path contains "\\Microsoft\\Excel\\Startup\\" and action_file_path endswith ".xll"))
