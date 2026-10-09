-- Title: Locked Workstation
-- ID: 411742ad-89b0-49cb-a7b0-3971b5c1e0a4
-- Status: stable
-- Level: informational
-- Author: Alexandr Yampolskyi, SOC Prime
-- Date: 2019-03-26
-- Tags: attack.impact
-- Description: Detects locked workstation session events that occur automatically after a standard period of inactivity.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (EventID = 4800)
