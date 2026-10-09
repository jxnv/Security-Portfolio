-- Title: Webshell ReGeorg Detection Via Web Logs
-- ID: 2ea44a60-cfda-11ea-87d0-0242ac130003
-- Status: test
-- Level: high
-- Author: Cian Heasley
-- Date: 2020-08-04
-- Tags: attack.persistence, attack.t1505.003
-- Description: Certain strings in the uri_query field when combined with null referer and null user agent can indicate activity associated with the webshell ReGeorg.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((cs-uri-query LIKE '%cmd=read%' OR cs-uri-query LIKE '%connect&target%' OR cs-uri-query LIKE '%cmd=connect%' OR cs-uri-query LIKE '%cmd=disconnect%' OR cs-uri-query LIKE '%cmd=forward%')) AND (NOT cs-referer=* AND NOT cs-user-agent=* AND cs-method = 'POST'))
