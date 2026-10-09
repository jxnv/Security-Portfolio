-- Title: MSExchange Transport Agent Installation
-- ID: 83809e84-4475-4b69-bc3e-4aad8568612f
-- Status: test
-- Level: medium
-- Author: Tobias Michalski (Nextron Systems)
-- Date: 2021-06-08
-- Tags: attack.persistence, attack.t1505.002
-- Description: Detects the Installation of a Exchange Transport Agent
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (CommandLine ILIKE '%Install-TransportAgent%')
