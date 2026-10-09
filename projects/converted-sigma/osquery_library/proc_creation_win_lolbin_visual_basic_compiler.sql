-- Title: Visual Basic Command Line Compiler Usage
-- ID: 7b10f171-7f04-47c7-9fa2-5be43c76e535
-- Status: test
-- Level: high
-- Author: Ensar Şamil, @sblmsrsn, @oscd_initiative
-- Date: 2020-10-07
-- Tags: attack.stealth, attack.t1027.004
-- Description: Detects successful code compilation via Visual Basic Command Line Compiler that utilizes Windows Resource to Object Converter.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (ParentImage="*\\vbc.exe" AND Image="*\\cvtres.exe")
