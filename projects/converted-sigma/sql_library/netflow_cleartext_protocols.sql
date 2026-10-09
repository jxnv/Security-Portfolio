-- Title: Cleartext Protocol Usage Via Netflow
-- ID: 7e4bfe58-4a47-4709-828d-d86c78b7cc1f
-- Status: stable
-- Level: low
-- Author: Alexandr Yampolskyi, SOC Prime
-- Date: 2019-03-26
-- Tags: attack.credential-access
-- Description: Ensure that all account usernames and authentication credentials are transmitted across networks using encrypted channels
-- Ensure that an encryption is used for all sensitive information in transit.
-- Ensure that an encrypted channels is used for all administrative account access.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((destination.port = 8080 OR destination.port = 21 OR destination.port = 80 OR destination.port = 23 OR destination.port = 50000 OR destination.port = 1521 OR destination.port = 27017 OR destination.port = 1433 OR destination.port = 11211 OR destination.port = 3306 OR destination.port = 15672 OR destination.port = 5900 OR destination.port = 5901 OR destination.port = 5902 OR destination.port = 5903 OR destination.port = 5904))
