-- Title: Local User Creation
-- ID: 66b6be3d-55d0-4f47-9855-d69df21740ea
-- Status: test
-- Level: low
-- Author: Patrick Bareiss
-- Date: 2019-04-18
-- Tags: attack.persistence, attack.t1136.001
-- Description: Detects local user creation on Windows servers, which shouldn't happen in an Active Directory environment. Apply this Sigma Use Case on your Windows server logs and not on your DC logs.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (EventID = 4720)
