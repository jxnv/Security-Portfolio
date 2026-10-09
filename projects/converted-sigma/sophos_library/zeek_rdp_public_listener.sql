-- Title: Publicly Accessible RDP Service
-- ID: 1fc0809e-06bf-4de3-ad52-25e5263b7623
-- Status: test
-- Level: high
-- Author: Josh Brower @DefensiveDepth
-- Date: 2020-08-22
-- Tags: attack.lateral-movement, attack.t1021.001
-- Description: Detects connections from routable IPs to an RDP listener. Which is indicative of a publicly-accessible RDP service.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE NOT (((cidrmatch("::1/128", id.orig_h) OR cidrmatch("10.0.0.0/8", id.orig_h) OR cidrmatch("127.0.0.0/8", id.orig_h) OR cidrmatch("172.16.0.0/12", id.orig_h) OR cidrmatch("192.168.0.0/16", id.orig_h) OR cidrmatch("169.254.0.0/16", id.orig_h) OR cidrmatch("2620:83:8000::/48", id.orig_h) OR cidrmatch("fc00::/7", id.orig_h) OR cidrmatch("fe80::/10", id.orig_h))))
