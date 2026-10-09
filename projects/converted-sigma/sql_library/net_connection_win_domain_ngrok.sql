-- Title: Process Initiated Network Connection To Ngrok Domain
-- ID: 18249279-932f-45e2-b37a-8925f2597670
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-07-16
-- Tags: attack.exfiltration, attack.command-and-control, attack.t1567, attack.t1572, attack.t1102
-- Description: Detects an executable initiating a network connection to "ngrok" domains.
-- Attackers were seen using this "ngrok" in order to store their second stage payloads and malware.
-- While communication with such domains can be legitimate, often times is a sign of either data exfiltration by malicious actors or additional download.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Initiated = 'true' AND (DestinationHostname ILIKE '%.ngrok-free.app' OR DestinationHostname ILIKE '%.ngrok-free.dev' OR DestinationHostname ILIKE '%.ngrok.app' OR DestinationHostname ILIKE '%.ngrok.dev' OR DestinationHostname ILIKE '%.ngrok.io'))
