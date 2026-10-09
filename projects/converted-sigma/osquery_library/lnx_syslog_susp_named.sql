-- Title: Suspicious Named Error
-- ID: c8e35e96-19ce-4f16-aeb6-fd5588dc5365
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2018-02-20
-- Tags: attack.initial-access, attack.t1190
-- Description: Detects suspicious DNS error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (" dropping source port zero packet from " OR " denied AXFR from " OR " exiting (due to fatal error)")
