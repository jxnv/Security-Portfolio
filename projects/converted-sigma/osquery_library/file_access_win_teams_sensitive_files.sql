-- Title: Microsoft Teams Sensitive File Access By Uncommon Applications
-- ID: 65744385-8541-44a6-8630-ffc824d7d4cc
-- Status: test
-- Level: medium
-- Author: @SerkinValery
-- Date: 2024-07-22
-- Tags: attack.credential-access, attack.t1528
-- Description: Detects file access attempts to sensitive Microsoft teams files (leveldb, cookies) by an uncommon process.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((FileName LIKE '%\\Microsoft\\Teams\\Cookies%' OR FileName LIKE '%\\Microsoft\\Teams\\Local Storage\\leveldb%')) AND NOT ((Image="*\\Microsoft\\Teams\\current\\Teams.exe")))
