// Title: Potential RjvPlatform.DLL Sideloading From Non-Default Location
// ID: 0e0bc253-07ed-43f1-816d-e1b220fe8971
// Status: test
// Level: high
// Author: X__Junior (Nextron Systems)
// Date: 2023-06-09
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects potential DLL sideloading of "RjvPlatform.dll" by "SystemResetPlatform.exe" located in a non-default location.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ImageLoaded endswith "\\RjvPlatform.dll" and action_process_image_path = "\\SystemResetPlatform.exe") and not ((action_process_image_path startswith "C:\\Windows\\System32\\SystemResetPlatform\\")))
