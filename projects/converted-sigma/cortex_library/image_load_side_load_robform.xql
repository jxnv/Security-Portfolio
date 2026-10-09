// Title: Potential RoboForm.DLL Sideloading
// ID: f64c9b2d-b0ad-481d-9d03-7fc75020892a
// Status: test
// Level: medium
// Author: X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-14
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects potential DLL sideloading of "roboform.dll", a DLL used by RoboForm Password Manager
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ImageLoaded endswith "\\roboform.dll" or ImageLoaded endswith "\\roboform-x64.dll")) and not (((action_process_image_path startswith " C:\\Program Files (x86)\\Siber Systems\\AI RoboForm\\" or action_process_image_path startswith " C:\\Program Files\\Siber Systems\\AI RoboForm\\") and (action_process_image_path endswith "\\robotaskbaricon.exe" or action_process_image_path endswith "\\robotaskbaricon-x64.exe"))))
