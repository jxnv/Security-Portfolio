-- Title: Suspicious Log Entries
-- ID: f64b6e9a-5d9d-48a5-8289-e1dd2b3876e1
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2017-03-25
-- Tags: attack.impact
-- Description: Detects suspicious log entries in Linux log files
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ("entered promiscuous mode" OR "Deactivating service" OR "Oversized packet received from" OR "imuxsock begins to drop messages")
