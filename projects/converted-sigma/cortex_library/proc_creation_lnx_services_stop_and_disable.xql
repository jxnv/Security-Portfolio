// Title: Disable Or Stop Services
// ID: de25eeb8-3655-4643-ac3a-b662d3f26b6b
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-15
// Tags: attack.defense-impairment, attack.t1685, attack.impact, attack.t1489
// Description: Detects the usage of utilities such as 'systemctl', 'service'...etc to stop or disable tools and services on Linux systems.
// Attackers may stop or disable security tools and services to evade detection, maintain persistence, or disrupt system operations.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "/service" or action_process_image_path endswith "/systemctl" or action_process_image_path endswith "/chkconfig") and (action_process_image_command_line contains " stop " or action_process_image_command_line contains " disable ")) and not (((action_process_image_path endswith "/systemctl" and (action_process_image_command_line contains "--no-reload disable snap-snapd-" or action_process_image_command_line contains " stop snap-snapd-")) or (action_process_image_path endswith "/systemctl" and actor_process_command_line contains "tmp.ci/preinst upgrade" and (action_process_image_command_line contains " stop " and action_process_image_command_line contains "ssh.")) or (actor_process_command_line contains "/dpkg/info/ubuntu-pro-client.prerm upgrade" and action_process_image_path endswith "/systemctl"))) and not ((action_process_image_path endswith "/systemctl" and action_process_image_command_line endswith "snap.amazon-ssm-agent.amazon-ssm-agent.service")))
