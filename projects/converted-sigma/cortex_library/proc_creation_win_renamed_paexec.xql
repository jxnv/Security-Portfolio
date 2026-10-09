// Title: Renamed PAExec Execution
// ID: c4e49831-1496-40cf-8ce1-b53f942b02f9
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Jason Lynch
// Date: 2021-05-22
// Tags: attack.stealth, attack.t1202
// Description: Detects execution of renamed version of PAExec. Often used by attackers
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((Description = "PAExec Application") or (action_process_image_name = "PAExec.exe") or (Product contains "PAExec") or ((Hashes contains "IMPHASH=11D40A7B7876288F919AB819CC2D9802" or Hashes contains "IMPHASH=6444f8a34e99b8f7d9647de66aabe516" or Hashes contains "IMPHASH=dfd6aa3f7b2b1035b76b718f1ddc689f" or Hashes contains "IMPHASH=1a6cca4d5460b1710a12dea39e4a592c"))) and not (((action_process_image_path endswith "\\paexec.exe") or (action_process_image_path startswith "C:\\Windows\\PAExec-"))))
