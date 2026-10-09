// Title: Webshell Tool Reconnaissance Activity
// ID: f64e5c19-879c-4bae-b471-6d84c8339677
// Status: test
// Level: high
// Author: Cian Heasley, Florian Roth (Nextron Systems)
// Date: 2020-07-22
// Tags: attack.persistence, attack.t1505.003
// Description: Detects processes spawned from web servers (PHP, Tomcat, IIS, etc.) that perform reconnaissance looking for the existence of popular scripting tools (perl, python, wget) on the system via the help commands
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((actor_process_image_path endswith "\\java.exe" or actor_process_image_path endswith "\\javaw.exe") and (actor_process_image_path contains "-tomcat-" or actor_process_image_path contains "\\tomcat")) or ((actor_process_image_path endswith "\\java.exe" or actor_process_image_path endswith "\\javaw.exe") and (action_process_image_command_line contains "CATALINA_HOME" or action_process_image_command_line contains "catalina.jar")) or ((actor_process_image_path endswith "\\caddy.exe" or actor_process_image_path endswith "\\httpd.exe" or actor_process_image_path endswith "\\nginx.exe" or actor_process_image_path endswith "\\php-cgi.exe" or actor_process_image_path endswith "\\w3wp.exe" or actor_process_image_path endswith "\\ws_tomcatservice.exe"))) and ((action_process_image_command_line contains "perl --help" or action_process_image_command_line contains "perl -h" or action_process_image_command_line contains "python --help" or action_process_image_command_line contains "python -h" or action_process_image_command_line contains "python3 --help" or action_process_image_command_line contains "python3 -h" or action_process_image_command_line contains "wget --help")))
