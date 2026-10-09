// Title: SQL Injection Strings In URI
// ID: 5513deaf-f49a-46c2-a6c8-3f111b5cb453
// Status: test
// Level: high
// Author: Saw Win Naung, Nasreddine Bencherchali (Nextron Systems), Thurein Oo (Yoma Bank)
// Date: 2020-02-22
// Tags: attack.initial-access, attack.t1190
// Description: Detects potential SQL injection attempts via GET requests in access logs.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((cs-method = "GET") and ("@@version" or "%271%27%3D%271" or "=select " or "=select(" or "=select%20" or "concat_ws(" or "CONCAT(0x" or "from mysql.innodb_table_stats" or "from%20mysql.innodb_table_stats" or "group_concat(" or "information_schema.tables" or "json_arrayagg(" or "or 1=1#" or "or%201=1#" or "order by " or "order%20by%20" or "select * " or "select database()" or "select version()" or "select%20*%20" or "select%20database()" or "select%20version()" or "select%28sleep%2810%29" or "SELECTCHAR(" or "table_schema" or "UNION ALL SELECT" or "UNION SELECT" or "UNION%20ALL%20SELECT" or "UNION%20SELECT" or "'1'='1") and not ((sc-status = 404)))
