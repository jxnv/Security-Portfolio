-- Title: File Time Attribute Change - Linux
-- ID: b3cec4e7-6901-4b0d-a02d-8ab2d8eb818b
-- Status: test
-- Level: medium
-- Author: Igor Fits, oscd.community
-- Date: 2020-10-15
-- Tags: attack.stealth, attack.t1070.006
-- Description: Detect file time attribute change to hide new or changes to existing files.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((type = 'EXECVE') AND ("touch") AND ("-t" OR "-acmr" OR "-d" OR "-r"))
