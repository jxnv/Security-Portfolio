// Title: Disable Security Tools
// ID: ff39f1a6-84ac-476f-a1af-37fcdf53d7c0
// Status: test
// Level: medium
// Author: Daniil Yugoslavskiy, oscd.community
// Date: 2020-10-19
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects disabling security tools
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image: "/bin/launchctl" AND CommandLine: "*unload*") AND ((CommandLine: "*com.objective-see.lulu.plist*" OR CommandLine: "*com.objective-see.blockblock.plist*" OR CommandLine: "*com.google.santad.plist*" OR CommandLine: "*com.carbonblack.defense.daemon.plist*" OR CommandLine: "*com.carbonblack.daemon.plist*" OR CommandLine: "*at.obdev.littlesnitchd.plist*" OR CommandLine: "*com.tenablesecurity.nessusagent.plist*" OR CommandLine: "*com.opendns.osx.RoamingClientConfigUpdater.plist*" OR CommandLine: "*com.crowdstrike.falcond.plist*" OR CommandLine: "*com.crowdstrike.userdaemon.plist*" OR CommandLine: "*osquery*" OR CommandLine: "*filebeat*" OR CommandLine: "*auditbeat*" OR CommandLine: "*packetbeat*" OR CommandLine: "*td-agent*"))) OR (Image: "/usr/sbin/spctl" AND CommandLine: "*disable*"))
