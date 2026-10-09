// Title: Potential Defense Evasion Via Binary Rename
// ID: 36480ae1-a1cb-4eaa-a0d6-29801d7e9142
// Status: test
// Level: medium
// Author: Matthew Green @mgreen27, Ecco, James Pemberton @4A616D6573, oscd.community, Andreas Hunkeler (@Karneades)
// Date: 2019-06-15
// Tags: attack.stealth, attack.t1036.003
// Description: Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_name = "Cmd.Exe" or action_process_image_name = "CONHOST.EXE" or action_process_image_name = "7z.exe" or action_process_image_name = "7za.exe" or action_process_image_name = "7zr.exe" or action_process_image_name = "WinRAR.exe" or action_process_image_name = "wevtutil.exe" or action_process_image_name = "net.exe" or action_process_image_name = "net1.exe" or action_process_image_name = "netsh.exe" or action_process_image_name = "InstallUtil.exe")) and not (((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\conhost.exe" or action_process_image_path endswith "\\7z.exe" or action_process_image_path endswith "\\7za.exe" or action_process_image_path endswith "\\7zr.exe" or action_process_image_path endswith "\\WinRAR.exe" or action_process_image_path endswith "\\wevtutil.exe" or action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe" or action_process_image_path endswith "\\netsh.exe" or action_process_image_path endswith "\\InstallUtil.exe"))))
