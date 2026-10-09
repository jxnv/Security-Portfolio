-- Title: AWS EC2 Disable EBS Encryption
-- ID: 16124c2d-e40b-4fcc-8f2c-5ab7870a2223
-- Status: stable
-- Level: medium
-- Author: Sittikorn S
-- Date: 2021-06-29
-- Tags: attack.impact, attack.t1486, attack.t1565
-- Description: Identifies disabling of default Amazon Elastic Block Store (EBS) encryption in the current region.
-- Disabling default encryption does not change the encryption status of your existing volumes.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (eventSource = 'ec2.amazonaws.com' AND eventName = 'DisableEbsEncryptionByDefault')
