-- Title: Cisco Show Commands Input
-- ID: b094d9fb-b1ad-4650-9f1a-fb7be9f1d34b
-- Status: test
-- Level: medium
-- Author: Austin Clark
-- Date: 2019-08-11
-- Tags: attack.credential-access, attack.t1552.003
-- Description: See what commands are being input into the device by other people, full credentials can be in the history
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ("show history" OR "show history all" OR "show logging")
