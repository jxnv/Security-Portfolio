// Title: LSASS Dump Keyword In CommandLine
// ID: ffa6861c-4461-4f59-8a41-578c39f3f23e
// Status: test
// Level: high
// Author: E.M. Anhaus, Tony Lambert, oscd.community, Nasreddine Bencherchali (Nextron Systems)
// Date: 2019-10-24
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects the presence of the keywords "lsass" and ".dmp" in the commandline, which could indicate a potential attempt to dump or create a dump of the lsass process.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "lsass.dmp" or action_process_image_command_line contains "lsass.zip" or action_process_image_command_line contains "lsass.rar" or action_process_image_command_line contains "Andrew.dmp" or action_process_image_command_line contains "Coredump.dmp" or action_process_image_command_line contains "NotLSASS.zip" or action_process_image_command_line contains "lsass_2" or action_process_image_command_line contains "lsassdump" or action_process_image_command_line contains "lsassdmp")) or ((action_process_image_command_line contains "lsass" and action_process_image_command_line contains ".dmp")) or ((action_process_image_command_line contains "SQLDmpr" and action_process_image_command_line contains ".mdmp")) or ((action_process_image_command_line contains "nanodump" and action_process_image_command_line contains ".dmp")))
