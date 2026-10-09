// Title: Bad Opsec Defaults Sacrificial Processes With Improper Arguments
// ID: a7c3d773-caef-227e-a7e7-c2f13c622329
// Status: test
// Level: high
// Author: Oleg Kolesnikov @securonix invrep_de, oscd.community, Florian Roth (Nextron Systems), Christian Burkard (Nextron Systems)
// Date: 2020-10-23
// Tags: attack.stealth, attack.t1218.011
// Description: Detects attackers using tooling with bad opsec defaults.
// E.g. spawning a sacrificial process to inject a capability into the process without taking into account how the process is normally run.
// One trivial example of this is using rundll32.exe without arguments as a sacrificial process (default in CS, now highlighted by c2lint), running WerFault without arguments (Kraken - credit am0nsec), and other examples.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\regasm.exe" and action_process_image_command_line endswith "regasm.exe") or (action_process_image_path endswith "\\regsvcs.exe" and action_process_image_command_line endswith "regsvcs.exe") or (action_process_image_path endswith "\\regsvr32.exe" and action_process_image_command_line endswith "regsvr32.exe") or (action_process_image_path endswith "\\rundll32.exe" and action_process_image_command_line endswith "rundll32.exe") or (action_process_image_path endswith "\\WerFault.exe" and action_process_image_command_line endswith "WerFault.exe")) and not ((((actor_process_image_path contains "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\Application\\" or actor_process_image_path contains "\\AppData\\Local\\Google\\Chrome\\Application\\") and actor_process_image_path endswith "\\Installer\\setup.exe" and actor_process_command_line contains "--uninstall " and action_process_image_path endswith "\\rundll32.exe" and action_process_image_command_line endswith "rundll32.exe") or (actor_process_image_path contains "\\AppData\\Local\\Microsoft\\EdgeUpdate\\Install\\{" and action_process_image_path endswith "\\rundll32.exe" and action_process_image_command_line endswith "rundll32.exe"))))
