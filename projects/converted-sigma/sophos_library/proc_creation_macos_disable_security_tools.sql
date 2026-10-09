-- Title: Disable Security Tools
-- ID: ff39f1a6-84ac-476f-a1af-37fcdf53d7c0
-- Status: test
-- Level: medium
-- Author: Daniil Yugoslavskiy, oscd.community
-- Date: 2020-10-19
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects disabling security tools
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Image = '/bin/launchctl' AND CommandLine ILIKE '%unload%') AND ((CommandLine ILIKE '%com.objective-see.lulu.plist%' OR CommandLine ILIKE '%com.objective-see.blockblock.plist%' OR CommandLine ILIKE '%com.google.santad.plist%' OR CommandLine ILIKE '%com.carbonblack.defense.daemon.plist%' OR CommandLine ILIKE '%com.carbonblack.daemon.plist%' OR CommandLine ILIKE '%at.obdev.littlesnitchd.plist%' OR CommandLine ILIKE '%com.tenablesecurity.nessusagent.plist%' OR CommandLine ILIKE '%com.opendns.osx.RoamingClientConfigUpdater.plist%' OR CommandLine ILIKE '%com.crowdstrike.falcond.plist%' OR CommandLine ILIKE '%com.crowdstrike.userdaemon.plist%' OR CommandLine ILIKE '%osquery%' OR CommandLine ILIKE '%filebeat%' OR CommandLine ILIKE '%auditbeat%' OR CommandLine ILIKE '%packetbeat%' OR CommandLine ILIKE '%td-agent%'))) OR (Image = '/usr/sbin/spctl' AND CommandLine ILIKE '%disable%'))
