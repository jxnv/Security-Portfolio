// Title: Linux Webshell Indicators
// ID: 818f7b24-0fba-4c49-a073-8b755573b9c7
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-10-15
// Tags: attack.persistence, attack.t1505.003
// Description: Detects suspicious sub processes of web server processes
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((actor_process_image_path endswith "/httpd" or actor_process_image_path endswith "/lighttpd" or actor_process_image_path endswith "/nginx" or actor_process_image_path endswith "/apache2" or actor_process_image_path endswith "/node" or actor_process_image_path endswith "/caddy")) or ((actor_process_command_line contains "/bin/java" and actor_process_command_line contains "tomcat")) or ((actor_process_command_line contains "/bin/java" and actor_process_command_line contains "websphere"))) and ((action_process_image_path endswith "/whoami" or action_process_image_path endswith "/ifconfig" or action_process_image_path endswith "/ip" or action_process_image_path endswith "/bin/uname" or action_process_image_path endswith "/bin/cat" or action_process_image_path endswith "/bin/crontab" or action_process_image_path endswith "/hostname" or action_process_image_path endswith "/iptables" or action_process_image_path endswith "/netstat" or action_process_image_path endswith "/pwd" or action_process_image_path endswith "/route")) and not ((actor_process_image_path endswith "/node" and action_process_image_command_line contains "ip neigh show")))
