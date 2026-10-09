// Title: Disable Security Tools
// ID: ff39f1a6-84ac-476f-a1af-37fcdf53d7c0
// Status: test
// Level: medium
// Author: Daniil Yugoslavskiy, oscd.community
// Date: 2020-10-19
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects disabling security tools
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path = "/bin/launchctl" and action_process_image_command_line contains "unload") and ((action_process_image_command_line contains "com.objective-see.lulu.plist" or action_process_image_command_line contains "com.objective-see.blockblock.plist" or action_process_image_command_line contains "com.google.santad.plist" or action_process_image_command_line contains "com.carbonblack.defense.daemon.plist" or action_process_image_command_line contains "com.carbonblack.daemon.plist" or action_process_image_command_line contains "at.obdev.littlesnitchd.plist" or action_process_image_command_line contains "com.tenablesecurity.nessusagent.plist" or action_process_image_command_line contains "com.opendns.osx.RoamingClientConfigUpdater.plist" or action_process_image_command_line contains "com.crowdstrike.falcond.plist" or action_process_image_command_line contains "com.crowdstrike.userdaemon.plist" or action_process_image_command_line contains "osquery" or action_process_image_command_line contains "filebeat" or action_process_image_command_line contains "auditbeat" or action_process_image_command_line contains "packetbeat" or action_process_image_command_line contains "td-agent"))) or (action_process_image_path = "/usr/sbin/spctl" and action_process_image_command_line contains "disable"))
