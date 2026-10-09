// Title: New Cron File Created
// ID: 6c4e2f43-d94d-4ead-b64d-97e53fa2bd05
// Status: experimental
// Level: low
// Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
// Date: 2021-10-15
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.003
// Description: Detects the creation of cron files in Cron directories, which could indicate potential persistence mechanisms being established by an attacker.
// Note that not all cron file creations are malicious - legitimate system administration activities and software installations may also create cron files.
// This detection should be investigated in context, considering factors such as the user creating the file, the timing of creation, and the contents of the cron job.
// Focus investigation on unexpected cron files created by non-administrative users or during suspicious timeframes.
// Additionally, it is recommended to review the contents of the newly created cron files to assess their intent.
// Furthermore, it is suggested to baseline normal cron file creation and apply additional filters to reduce false positives based on the specific environment.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_file_path startswith "/etc/cron.d/" or action_file_path startswith "/etc/cron.daily/" or action_file_path startswith "/etc/cron.hourly/" or action_file_path startswith "/etc/cron.monthly/" or action_file_path startswith "/etc/cron.weekly/" or action_file_path startswith "/var/spool/cron/crontabs/" or action_file_path startswith "/var/spool/cron/root")) or ((action_file_path contains "/etc/cron.allow" or action_file_path contains "/etc/cron.deny" or action_file_path contains "/etc/crontab"))) and not (((action_file_path = "/etc/cron.daily/apt" or action_file_path = "/etc/cron.daily/dpkg" or action_file_path = "/etc/cron.daily/passwd" or action_file_path = "/etc/crontabs/root"))))
