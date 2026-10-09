-- Title: Msxsl.EXE Execution
-- ID: 9e50a8b3-dd05-4eb8-9153-bdb6b79d50b0
-- Status: test
-- Level: medium
-- Author: Timur Zinniatullin, oscd.community
-- Date: 2019-10-21
-- Tags: attack.stealth, attack.t1220
-- Description: Detects the execution of the MSXSL utility. This can be used to execute Extensible Stylesheet Language (XSL) files. These files are commonly used to describe the processing and rendering of data within XML files.
-- Adversaries can abuse this functionality to execute arbitrary files while potentially bypassing application whitelisting defenses.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Image ILIKE '%\\msxsl.exe')
