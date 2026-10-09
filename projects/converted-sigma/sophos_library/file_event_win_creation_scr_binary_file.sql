-- Title: Suspicious Screensaver Binary File Creation
-- ID: 97aa2e88-555c-450d-85a6-229bcd87efb8
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-12-29
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1546.002
-- Description: Adversaries may establish persistence by executing malicious content triggered by user inactivity.
-- Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetFilename ILIKE '%.scr') AND NOT ((((Image ILIKE '%\\Kindle.exe' OR Image ILIKE '%\\Bin\\ccSvcHst.exe')) OR (Image ILIKE '%\\TiWorker.exe' AND TargetFilename ILIKE '%\\uwfservicingscr.scr'))))
