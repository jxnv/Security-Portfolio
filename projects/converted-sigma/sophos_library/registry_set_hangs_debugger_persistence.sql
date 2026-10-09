-- Title: Add Debugger Entry To Hangs Key For Persistence
-- ID: 833ef470-fa01-4631-a79b-6f291c9ac498
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-21
-- Tags: attack.persistence
-- Description: Detects when an attacker adds a new "Debugger" value to the "Hangs" key in order to achieve persistence which will get invoked when an application crashes
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (TargetObject ILIKE '%\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\Hangs\\Debugger%')
