-- Title: Windows Screen Capture with CopyFromScreen
-- ID: d4a11f63-2390-411c-9adf-d791fd152830
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-12-28
-- Tags: attack.collection, attack.t1113
-- Description: Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation.
-- Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (ScriptBlockText ILIKE '%.CopyFromScreen%')
