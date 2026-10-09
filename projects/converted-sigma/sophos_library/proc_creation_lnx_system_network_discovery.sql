-- Title: System Network Discovery - Linux
-- ID: e7bd1cfa-b446-4c88-8afb-403bcd79e3fa
-- Status: test
-- Level: informational
-- Author: Ömer Günal and remotephone, oscd.community
-- Date: 2020-10-06
-- Tags: attack.discovery, attack.t1016
-- Description: Detects enumeration of local network configuration
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%/etc/resolv.conf%') OR ((Image ILIKE '%/firewall-cmd' OR Image ILIKE '%/ufw' OR Image ILIKE '%/iptables' OR Image ILIKE '%/netstat' OR Image ILIKE '%/ss' OR Image ILIKE '%/ip' OR Image ILIKE '%/ifconfig' OR Image ILIKE '%/systemd-resolve' OR Image ILIKE '%/route')))
