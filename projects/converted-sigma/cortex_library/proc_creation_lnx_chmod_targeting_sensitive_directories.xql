// Title: Chmod Targeting Sensitive Directories
// ID: 6419afd1-3742-47a5-a7e6-b50386cd15f8
// Status: test
// Level: medium
// Author: Christopher Peacock @SecurePeacock, SCYTHE @scythe_io
// Date: 2022-06-03
// Tags: attack.defense-impairment, attack.t1222.002
// Description: Detects chmod targeting files in sensitive directory paths on Linux systems.
// Attackers may use chmod to change permissions of files in these directories to maintain persistence, escalate privileges, or disrupt system operations.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/chmod" and (action_process_image_command_line contains "/tmp/" or action_process_image_command_line contains "/.Library/" or action_process_image_command_line contains "/etc/" or action_process_image_command_line contains "/opt/")) and not (((action_process_image_command_line startswith "chmod 700 /tmp/apt-key-gpghome.") or (action_process_image_command_line = "chmod 0775 /etc/landscape/") or (action_process_image_command_line startswith "chmod 755 /var/tmp/mkinitramfs") or (action_process_image_command_line contains "/etc/" and (actor_process_command_line contains "/var/lib/dpkg/info/" and actor_process_command_line contains ".postinst configure")) or (action_process_image_command_line = "chmod 644 /etc/apparmor.d/tunables/home.d/ubuntu") or (action_process_image_command_line contains "chmod --reference=/etc/shells" and actor_process_command_line endswith "/update-shells"))))
