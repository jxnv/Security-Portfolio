// Title: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)
// ID: 2afafd61-6aae-4df4-baed-139fa1f4c345
// Status: test
// Level: medium
// Author: Thomas Patzke
// Date: 2019-01-16
// Tags: attack.credential-access, attack.t1003.003
// Description: Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\ntdsutil.exe")
