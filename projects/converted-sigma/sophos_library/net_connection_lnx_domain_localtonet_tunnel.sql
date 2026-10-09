-- Title: Communication To LocaltoNet Tunneling Service Initiated - Linux
-- ID: c4568f5d-131f-4e78-83d4-45b2da0ec4f1
-- Status: test
-- Level: high
-- Author: Andreas Braathen (mnemonic.io)
-- Date: 2024-06-17
-- Tags: attack.command-and-control, attack.t1572, attack.t1090, attack.t1102
-- Description: Detects an executable initiating a network connection to "LocaltoNet" tunneling sub-domains.
-- LocaltoNet is a reverse proxy that enables localhost services to be exposed to the Internet.
-- Attackers have been seen to use this service for command-and-control activities to bypass MFA and perimeter controls.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((DestinationHostname ILIKE '%.localto.net' OR DestinationHostname ILIKE '%.localtonet.com') AND Initiated = 'true')
