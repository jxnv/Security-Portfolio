-- Title: Webshell ReGeorg Detection Via Web Logs
-- ID: 2ea44a60-cfda-11ea-87d0-0242ac130003
-- Status: test
-- Level: high
-- Author: Cian Heasley
-- Date: 2020-08-04
-- Tags: attack.persistence, attack.t1505.003
-- Description: Certain strings in the uri_query field when combined with null referer and null user agent can indicate activity associated with the webshell ReGeorg.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((cs-uri-query ILIKE '%cmd=read%' OR cs-uri-query ILIKE '%connect&target%' OR cs-uri-query ILIKE '%cmd=connect%' OR cs-uri-query ILIKE '%cmd=disconnect%' OR cs-uri-query ILIKE '%cmd=forward%')) AND (cs-referer IS NULL AND cs-user-agent IS NULL AND cs-method = 'POST'))
