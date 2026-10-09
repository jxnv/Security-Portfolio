// Title: HackTool - PPID Spoofing SelectMyParent Tool Execution
// ID: 52ff7941-8211-46f9-84f8-9903efb7077d
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-07-23
// Tags: attack.privilege-escalation, attack.stealth, attack.t1134.004
// Description: Detects the use of parent process ID spoofing tools like Didier Stevens tool SelectMyParent
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\SelectMyParent.exe") or ((action_process_image_command_line contains "PPID-spoof" or action_process_image_command_line contains "ppid_spoof" or action_process_image_command_line contains "spoof-ppid" or action_process_image_command_line contains "spoof_ppid" or action_process_image_command_line contains "ppidspoof" or action_process_image_command_line contains "spoofppid" or action_process_image_command_line contains "spoofedppid" or action_process_image_command_line contains " -spawnto ")) or ((action_process_image_name contains "PPID-spoof" or action_process_image_name contains "ppid_spoof" or action_process_image_name contains "spoof-ppid" or action_process_image_name contains "spoof_ppid" or action_process_image_name contains "ppidspoof" or action_process_image_name contains "spoofppid" or action_process_image_name contains "spoofedppid")) or (Description = "SelectMyParent") or ((Hashes contains "IMPHASH=04D974875BD225F00902B4CAD9AF3FBC" or Hashes contains "IMPHASH=A782AF154C9E743DDF3F3EB2B8F3D16E" or Hashes contains "IMPHASH=89059503D7FBF470E68F7E63313DA3AD" or Hashes contains "IMPHASH=CA28337632625C8281AB8A130B3D6BAD")))
