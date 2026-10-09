-- Title: System Network Discovery - macOS
-- ID: 58800443-f9fc-4d55-ae0c-98a3966dfb97
-- Status: test
-- Level: informational
-- Author: remotephone, oscd.community
-- Date: 2020-10-06
-- Tags: attack.discovery, attack.t1016
-- Description: Detects enumeration of local network configuration
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((Image="*/arp" OR Image="*/ifconfig" OR Image="*/netstat" OR Image="*/networksetup" OR Image="*/socketfilterfw")) OR (Image = '/usr/bin/defaults' AND (CommandLine LIKE '%/Library/Preferences/com.apple.alf%' AND CommandLine LIKE '%read%'))) AND NOT ((ParentImage="*/wifivelocityd")))
