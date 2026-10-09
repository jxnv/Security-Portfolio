-- Title: Disable Security Tools
-- ID: ff39f1a6-84ac-476f-a1af-37fcdf53d7c0
-- Status: test
-- Level: medium
-- Author: Daniil Yugoslavskiy, oscd.community
-- Date: 2020-10-19
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects disabling security tools
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image = '/bin/launchctl' AND CommandLine LIKE '%unload%') AND ((CommandLine LIKE '%com.objective-see.lulu.plist%' OR CommandLine LIKE '%com.objective-see.blockblock.plist%' OR CommandLine LIKE '%com.google.santad.plist%' OR CommandLine LIKE '%com.carbonblack.defense.daemon.plist%' OR CommandLine LIKE '%com.carbonblack.daemon.plist%' OR CommandLine LIKE '%at.obdev.littlesnitchd.plist%' OR CommandLine LIKE '%com.tenablesecurity.nessusagent.plist%' OR CommandLine LIKE '%com.opendns.osx.RoamingClientConfigUpdater.plist%' OR CommandLine LIKE '%com.crowdstrike.falcond.plist%' OR CommandLine LIKE '%com.crowdstrike.userdaemon.plist%' OR CommandLine LIKE '%osquery%' OR CommandLine LIKE '%filebeat%' OR CommandLine LIKE '%auditbeat%' OR CommandLine LIKE '%packetbeat%' OR CommandLine LIKE '%td-agent%'))) OR (Image = '/usr/sbin/spctl' AND CommandLine LIKE '%disable%'))
