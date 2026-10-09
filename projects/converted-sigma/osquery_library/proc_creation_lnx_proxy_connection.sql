-- Title: Connection Proxy
-- ID: 72f4ab3f-787d-495d-a55d-68c2ff46cf4c
-- Status: test
-- Level: low
-- Author: Ömer Günal
-- Date: 2020-06-17
-- Tags: attack.command-and-control, attack.t1090
-- Description: Detects setting proxy configuration
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%http_proxy=%' OR CommandLine LIKE '%https_proxy=%'))
