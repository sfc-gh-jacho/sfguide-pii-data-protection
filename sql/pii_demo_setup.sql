/*
================================================================================
 PROTECTING PII IN SNOWFLAKE - DEMO SCRIPT
 Demonstrates Snowflake Horizon data governance features:
 - Sensitive Data Classification (automatic PII discovery)
 - Object Tagging and Tag-based Masking
 - Dynamic Data Masking (column-level security)
 - Row Access Policies (row-level security)
 - Role-based access control and role-based views

 BEFORE YOU RUN: replace these placeholders throughout the script
   <YOUR_WAREHOUSE>  - a warehouse you can use (e.g. COMPUTE_WH)
   <YOUR_DATABASE>   - an existing database to hold the demo schema

 Requires Enterprise Edition (or higher). Run as ACCOUNTADMIN, or as
 <YOUR_ROLE> with equivalent privileges (see README).

 ALL DATA IN THIS SCRIPT IS SYNTHETIC. No real people are represented.
================================================================================
*/

-- [step:setup]
-- ============================================================================
-- STEP 1: SETUP - Schema and Table Creation
-- ============================================================================

USE ROLE ACCOUNTADMIN;
USE WAREHOUSE <YOUR_WAREHOUSE>;
USE DATABASE <YOUR_DATABASE>;

-- Create dedicated schema for this demo
CREATE SCHEMA IF NOT EXISTS DEMODATASECURITY;
USE SCHEMA DEMODATASECURITY;

-- Create the CUSTOMERS table with various PII fields
CREATE OR REPLACE TABLE CUSTOMERS (
    -- Identifiers
    CUSTOMER_ID         NUMBER AUTOINCREMENT PRIMARY KEY,
    CUSTOMER_TYPE       VARCHAR(20) NOT NULL,      -- STANDARD, VIP, INTERNAL
    REGION              VARCHAR(10) NOT NULL,       -- NORTH, SOUTH, EAST, WEST

    -- Name (PII)
    FIRST_NAME          VARCHAR(50) NOT NULL,
    LAST_NAME           VARCHAR(50) NOT NULL,

    -- Contact Information (PII)
    EMAIL               VARCHAR(100) NOT NULL,
    PHONE_NUMBER        VARCHAR(20),                -- xxx-xxx-xxxx format
    MOBILE_NUMBER       VARCHAR(20),                -- xxx-xxx-xxxx format

    -- Identity Information (Sensitive PII)
    DATE_OF_BIRTH       DATE,
    SSN                 VARCHAR(11),                -- xxx-xx-xxxx format
    DRIVERS_LICENSE     VARCHAR(20),

    -- Address (PII)
    STREET_ADDRESS      VARCHAR(200),
    CITY                VARCHAR(100),
    STATE               VARCHAR(2),
    ZIP_CODE            VARCHAR(10),
    COUNTRY             VARCHAR(50) DEFAULT 'USA',

    -- Financial (Highly Sensitive PII)
    CREDIT_CARD_NUMBER  VARCHAR(19),                -- xxxx-xxxx-xxxx-xxxx format
    BANK_ACCOUNT        VARCHAR(20),

    -- Metadata
    MEMBERSHIP_LEVEL    VARCHAR(20),                -- BRONZE, SILVER, GOLD, PLATINUM
    CREATED_AT          TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

-- [step:roles]
-- ============================================================================
-- STEP 2: ROLES - Create Role Hierarchy
-- ============================================================================

-- Create the four demo roles
CREATE ROLE IF NOT EXISTS PII_ADMIN;
CREATE ROLE IF NOT EXISTS PII_ANALYST;
CREATE ROLE IF NOT EXISTS PII_SUPPORT;
CREATE ROLE IF NOT EXISTS PII_MARKETING;

-- Grant roles to ACCOUNTADMIN for easy switching during demo
GRANT ROLE PII_ADMIN TO ROLE ACCOUNTADMIN;
GRANT ROLE PII_ANALYST TO ROLE ACCOUNTADMIN;
GRANT ROLE PII_SUPPORT TO ROLE ACCOUNTADMIN;
GRANT ROLE PII_MARKETING TO ROLE ACCOUNTADMIN;

-- Grant warehouse usage to all roles
GRANT USAGE ON WAREHOUSE <YOUR_WAREHOUSE> TO ROLE PII_ADMIN;
GRANT USAGE ON WAREHOUSE <YOUR_WAREHOUSE> TO ROLE PII_ANALYST;
GRANT USAGE ON WAREHOUSE <YOUR_WAREHOUSE> TO ROLE PII_SUPPORT;
GRANT USAGE ON WAREHOUSE <YOUR_WAREHOUSE> TO ROLE PII_MARKETING;

-- Grant database and schema usage
GRANT USAGE ON DATABASE <YOUR_DATABASE> TO ROLE PII_ADMIN;
GRANT USAGE ON DATABASE <YOUR_DATABASE> TO ROLE PII_ANALYST;
GRANT USAGE ON DATABASE <YOUR_DATABASE> TO ROLE PII_SUPPORT;
GRANT USAGE ON DATABASE <YOUR_DATABASE> TO ROLE PII_MARKETING;

GRANT USAGE ON SCHEMA <YOUR_DATABASE>.DEMODATASECURITY TO ROLE PII_ADMIN;
GRANT USAGE ON SCHEMA <YOUR_DATABASE>.DEMODATASECURITY TO ROLE PII_ANALYST;
GRANT USAGE ON SCHEMA <YOUR_DATABASE>.DEMODATASECURITY TO ROLE PII_SUPPORT;
GRANT USAGE ON SCHEMA <YOUR_DATABASE>.DEMODATASECURITY TO ROLE PII_MARKETING;

-- Grant SELECT on the CUSTOMERS table to all roles
GRANT SELECT ON TABLE CUSTOMERS TO ROLE PII_ADMIN;
GRANT SELECT ON TABLE CUSTOMERS TO ROLE PII_ANALYST;
GRANT SELECT ON TABLE CUSTOMERS TO ROLE PII_SUPPORT;
GRANT SELECT ON TABLE CUSTOMERS TO ROLE PII_MARKETING;

-- [step:masking]
-- ============================================================================
-- STEP 3: MASKING POLICIES
-- ============================================================================

-- 3.1 SSN Masking Policy
-- PII_ADMIN: Full access
-- All others: Fully masked (***-**-****)
CREATE OR REPLACE MASKING POLICY mask_ssn AS (val STRING) RETURNS STRING ->
    CASE
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'PII_ADMIN') THEN val
        ELSE '***-**-****'
    END;

-- 3.2 Date of Birth Masking Policy
-- PII_ADMIN: Full date
-- PII_ANALYST: Year only
-- Others: Fully masked
CREATE OR REPLACE MASKING POLICY mask_dob AS (val DATE) RETURNS DATE ->
    CASE
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'PII_ADMIN') THEN val
        WHEN CURRENT_ROLE() = 'PII_ANALYST' THEN DATE_TRUNC('YEAR', val)
        ELSE NULL
    END;

-- 3.3 Phone Number Masking Policy
-- PII_ADMIN, PII_SUPPORT: Full number
-- PII_ANALYST: Last 4 digits only
-- PII_MARKETING: Fully masked
CREATE OR REPLACE MASKING POLICY mask_phone AS (val STRING) RETURNS STRING ->
    CASE
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'PII_ADMIN', 'PII_SUPPORT') THEN val
        WHEN CURRENT_ROLE() = 'PII_ANALYST' THEN CONCAT('***-***-', RIGHT(val, 4))
        ELSE '***-***-****'
    END;

-- 3.4 Email Masking Policy
-- PII_ADMIN, PII_SUPPORT: Full email
-- PII_ANALYST, PII_MARKETING: Domain only (****@domain.com)
CREATE OR REPLACE MASKING POLICY mask_email AS (val STRING) RETURNS STRING ->
    CASE
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'PII_ADMIN', 'PII_SUPPORT') THEN val
        WHEN CURRENT_ROLE() IN ('PII_ANALYST', 'PII_MARKETING') THEN
            CONCAT('****@', SPLIT_PART(val, '@', 2))
        ELSE '****@****.***'
    END;

-- 3.5 Credit Card Masking Policy
-- PII_ADMIN: Full number
-- PII_ANALYST: Last 4 digits
-- Others: Fully masked
CREATE OR REPLACE MASKING POLICY mask_credit_card AS (val STRING) RETURNS STRING ->
    CASE
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'PII_ADMIN') THEN val
        WHEN CURRENT_ROLE() = 'PII_ANALYST' THEN CONCAT('****-****-****-', RIGHT(val, 4))
        ELSE '****-****-****-****'
    END;

-- 3.6 Street Address Masking Policy
-- PII_ADMIN, PII_ANALYST, PII_SUPPORT: Full address
-- PII_MARKETING: Masked
CREATE OR REPLACE MASKING POLICY mask_address AS (val STRING) RETURNS STRING ->
    CASE
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'PII_ADMIN', 'PII_ANALYST', 'PII_SUPPORT') THEN val
        ELSE '*** STREET ADDRESS HIDDEN ***'
    END;

-- 3.7 Bank Account Masking Policy
-- PII_ADMIN: Full number
-- All others: Fully masked
CREATE OR REPLACE MASKING POLICY mask_bank_account AS (val STRING) RETURNS STRING ->
    CASE
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'PII_ADMIN') THEN val
        ELSE '**********'
    END;

-- 3.8 Drivers License Masking Policy
-- PII_ADMIN: Full number
-- PII_ANALYST: Last 4 characters
-- Others: Fully masked
CREATE OR REPLACE MASKING POLICY mask_drivers_license AS (val STRING) RETURNS STRING ->
    CASE
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'PII_ADMIN') THEN val
        WHEN CURRENT_ROLE() = 'PII_ANALYST' THEN CONCAT('****', RIGHT(val, 4))
        ELSE '********'
    END;

-- [step:rowaccess]
-- ============================================================================
-- STEP 4: ROW ACCESS POLICY
-- ============================================================================

-- Row Access Policy based on CUSTOMER_TYPE
-- PII_ADMIN, PII_ANALYST: All rows
-- PII_SUPPORT: Only STANDARD customers
-- PII_MARKETING: STANDARD and VIP only (no INTERNAL)
CREATE OR REPLACE ROW ACCESS POLICY customer_row_access AS (customer_type_val STRING) RETURNS BOOLEAN ->
    CASE
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'PII_ADMIN', 'PII_ANALYST') THEN TRUE
        WHEN CURRENT_ROLE() = 'PII_SUPPORT' AND customer_type_val = 'STANDARD' THEN TRUE
        WHEN CURRENT_ROLE() = 'PII_MARKETING' AND customer_type_val IN ('STANDARD', 'VIP') THEN TRUE
        ELSE FALSE
    END;

-- [step:apply]
-- ============================================================================
-- STEP 5: APPLY POLICIES TO TABLE
-- ============================================================================

-- Apply masking policies to columns
ALTER TABLE CUSTOMERS MODIFY COLUMN SSN SET MASKING POLICY mask_ssn;
ALTER TABLE CUSTOMERS MODIFY COLUMN DATE_OF_BIRTH SET MASKING POLICY mask_dob;
ALTER TABLE CUSTOMERS MODIFY COLUMN PHONE_NUMBER SET MASKING POLICY mask_phone;
ALTER TABLE CUSTOMERS MODIFY COLUMN MOBILE_NUMBER SET MASKING POLICY mask_phone;
ALTER TABLE CUSTOMERS MODIFY COLUMN EMAIL SET MASKING POLICY mask_email;
ALTER TABLE CUSTOMERS MODIFY COLUMN CREDIT_CARD_NUMBER SET MASKING POLICY mask_credit_card;
ALTER TABLE CUSTOMERS MODIFY COLUMN STREET_ADDRESS SET MASKING POLICY mask_address;
ALTER TABLE CUSTOMERS MODIFY COLUMN BANK_ACCOUNT SET MASKING POLICY mask_bank_account;
ALTER TABLE CUSTOMERS MODIFY COLUMN DRIVERS_LICENSE SET MASKING POLICY mask_drivers_license;

-- Apply row access policy
ALTER TABLE CUSTOMERS ADD ROW ACCESS POLICY customer_row_access ON (CUSTOMER_TYPE);

-- [step:data]
-- ============================================================================
-- STEP 6: SAMPLE DATA - 98 Synthetic Customer Records
-- ============================================================================

INSERT INTO CUSTOMERS (CUSTOMER_TYPE, REGION, FIRST_NAME, LAST_NAME, EMAIL, PHONE_NUMBER, MOBILE_NUMBER, DATE_OF_BIRTH, SSN, DRIVERS_LICENSE, STREET_ADDRESS, CITY, STATE, ZIP_CODE, COUNTRY, CREDIT_CARD_NUMBER, BANK_ACCOUNT, MEMBERSHIP_LEVEL)
VALUES
-- STANDARD Customers (58 records)
('STANDARD', 'NORTH', 'John', 'Smith', 'john.smith@gmail.com', '555-123-4567', '555-987-6543', '1985-03-15', '123-45-6789', 'D1234567', '123 Main Street', 'New York', 'NY', '10001', 'USA', '4111-1111-1111-1111', '1234567890', 'BRONZE'),
('STANDARD', 'SOUTH', 'Emily', 'Johnson', 'emily.j@yahoo.com', '555-234-5678', '555-876-5432', '1990-07-22', '234-56-7890', 'D2345678', '456 Oak Avenue', 'Miami', 'FL', '33101', 'USA', '4222-2222-2222-2222', '2345678901', 'SILVER'),
('STANDARD', 'EAST', 'Michael', 'Williams', 'mwilliams@outlook.com', '555-345-6789', '555-765-4321', '1978-11-08', '345-67-8901', 'D3456789', '789 Pine Road', 'Boston', 'MA', '02101', 'USA', '4333-3333-3333-3333', '3456789012', 'GOLD'),
('STANDARD', 'WEST', 'Sarah', 'Brown', 'sarah.brown@gmail.com', '555-456-7890', '555-654-3210', '1992-01-30', '456-78-9012', 'D4567890', '321 Cedar Lane', 'Los Angeles', 'CA', '90001', 'USA', '4444-4444-4444-4444', '4567890123', 'BRONZE'),
('STANDARD', 'NORTH', 'David', 'Jones', 'djones@hotmail.com', '555-567-8901', '555-543-2109', '1988-05-12', '567-89-0123', 'D5678901', '654 Maple Drive', 'Chicago', 'IL', '60601', 'USA', '4555-5555-5555-5555', '5678901234', 'SILVER'),
('STANDARD', 'SOUTH', 'Jennifer', 'Garcia', 'jen.garcia@gmail.com', '555-678-9012', '555-432-1098', '1995-09-25', '678-90-1234', 'D6789012', '987 Elm Street', 'Houston', 'TX', '77001', 'USA', '4666-6666-6666-6666', '6789012345', 'BRONZE'),
('STANDARD', 'EAST', 'Christopher', 'Miller', 'cmiller@yahoo.com', '555-789-0123', '555-321-0987', '1982-12-03', '789-01-2345', 'D7890123', '147 Birch Way', 'Philadelphia', 'PA', '19101', 'USA', '4777-7777-7777-7777', '7890123456', 'PLATINUM'),
('STANDARD', 'WEST', 'Amanda', 'Davis', 'amanda.d@outlook.com', '555-890-1234', '555-210-9876', '1987-04-18', '890-12-3456', 'D8901234', '258 Walnut Court', 'Phoenix', 'AZ', '85001', 'USA', '4888-8888-8888-8888', '8901234567', 'SILVER'),
('STANDARD', 'NORTH', 'Daniel', 'Rodriguez', 'drodriguez@gmail.com', '555-901-2345', '555-109-8765', '1993-08-07', '901-23-4567', 'D9012345', '369 Spruce Place', 'Detroit', 'MI', '48201', 'USA', '4999-9999-9999-9999', '9012345678', 'GOLD'),
('STANDARD', 'SOUTH', 'Jessica', 'Martinez', 'jmartinez@yahoo.com', '555-012-3456', '555-098-7654', '1980-02-14', '012-34-5678', 'D0123456', '741 Ash Boulevard', 'Atlanta', 'GA', '30301', 'USA', '5000-0000-0000-0000', '0123456789', 'BRONZE'),
('STANDARD', 'EAST', 'Matthew', 'Hernandez', 'matt.h@gmail.com', '555-111-2222', '555-333-4444', '1991-06-29', '111-22-3333', 'D1112223', '852 Hickory Lane', 'Baltimore', 'MD', '21201', 'USA', '5111-1111-1111-1111', '1112223334', 'SILVER'),
('STANDARD', 'WEST', 'Ashley', 'Lopez', 'alopez@hotmail.com', '555-222-3333', '555-444-5555', '1984-10-11', '222-33-4444', 'D2223334', '963 Willow Street', 'San Diego', 'CA', '92101', 'USA', '5222-2222-2222-2222', '2223334445', 'GOLD'),
('STANDARD', 'NORTH', 'Joshua', 'Gonzalez', 'jgonzalez@outlook.com', '555-333-4444', '555-555-6666', '1996-01-05', '333-44-5555', 'D3334445', '174 Poplar Road', 'Cleveland', 'OH', '44101', 'USA', '5333-3333-3333-3333', '3334445556', 'BRONZE'),
('STANDARD', 'SOUTH', 'Stephanie', 'Wilson', 'swilson@gmail.com', '555-444-5555', '555-666-7777', '1989-03-20', '444-55-6666', 'D4445556', '285 Sycamore Drive', 'Orlando', 'FL', '32801', 'USA', '5444-4444-4444-4444', '4445556667', 'PLATINUM'),
('STANDARD', 'EAST', 'Andrew', 'Anderson', 'aanderson@yahoo.com', '555-555-6666', '555-777-8888', '1977-07-16', '555-66-7777', 'D5556667', '396 Magnolia Avenue', 'Pittsburgh', 'PA', '15201', 'USA', '5555-5555-5555-5555', '5556667778', 'SILVER'),
('STANDARD', 'WEST', 'Nicole', 'Thomas', 'nthomas@gmail.com', '555-666-7777', '555-888-9999', '1994-11-28', '666-77-8888', 'D6667778', '507 Chestnut Way', 'San Jose', 'CA', '95101', 'USA', '5666-6666-6666-6666', '6667778889', 'BRONZE'),
('STANDARD', 'NORTH', 'Ryan', 'Taylor', 'rtaylor@hotmail.com', '555-777-8888', '555-999-0000', '1986-05-09', '777-88-9999', 'D7778889', '618 Beech Court', 'Minneapolis', 'MN', '55401', 'USA', '5777-7777-7777-7777', '7778889990', 'GOLD'),
('STANDARD', 'SOUTH', 'Lauren', 'Moore', 'lmoore@outlook.com', '555-888-9999', '555-000-1111', '1983-09-02', '888-99-0000', 'D8889990', '729 Locust Place', 'Tampa', 'FL', '33601', 'USA', '5888-8888-8888-8888', '8889990001', 'SILVER'),
('STANDARD', 'EAST', 'Kevin', 'Jackson', 'kjackson@gmail.com', '555-999-0000', '555-111-2223', '1997-12-17', '999-00-1111', 'D9990001', '840 Juniper Lane', 'Newark', 'NJ', '07101', 'USA', '5999-9999-9999-9999', '9990001112', 'BRONZE'),
('STANDARD', 'WEST', 'Megan', 'Martin', 'mmartin@yahoo.com', '555-000-1111', '555-222-3334', '1981-04-24', '000-11-2222', 'D0001112', '951 Cypress Road', 'Sacramento', 'CA', '95814', 'USA', '6000-0000-0000-0000', '0001112223', 'PLATINUM'),
('STANDARD', 'NORTH', 'Brian', 'Lee', 'blee@gmail.com', '555-100-2000', '555-300-4000', '1990-08-13', '100-20-3000', 'D1002003', '162 Oak Hill Drive', 'Milwaukee', 'WI', '53201', 'USA', '6100-1000-2000-3000', '1002003004', 'SILVER'),
('STANDARD', 'SOUTH', 'Rachel', 'Perez', 'rperez@hotmail.com', '555-200-3000', '555-400-5000', '1976-02-28', '200-30-4000', 'D2003004', '273 Pine Valley Lane', 'New Orleans', 'LA', '70112', 'USA', '6200-2000-3000-4000', '2003004005', 'GOLD'),
('STANDARD', 'EAST', 'Justin', 'Thompson', 'jthompson@outlook.com', '555-300-4000', '555-500-6000', '1998-06-06', '300-40-5000', 'D3004005', '384 Cedar Grove Way', 'Hartford', 'CT', '06101', 'USA', '6300-3000-4000-5000', '3004005006', 'BRONZE'),
('STANDARD', 'WEST', 'Heather', 'White', 'hwhite@gmail.com', '555-400-5000', '555-600-7000', '1985-10-19', '400-50-6000', 'D4005006', '495 Maple Ridge Court', 'Denver', 'CO', '80201', 'USA', '6400-4000-5000-6000', '4005006007', 'SILVER'),
('STANDARD', 'NORTH', 'Brandon', 'Harris', 'bharris@yahoo.com', '555-500-6000', '555-700-8000', '1992-01-31', '500-60-7000', 'D5006007', '606 Elm Creek Place', 'Indianapolis', 'IN', '46201', 'USA', '6500-5000-6000-7000', '5006007008', 'PLATINUM'),
('STANDARD', 'SOUTH', 'Samantha', 'Sanchez', 'ssanchez@gmail.com', '555-600-7000', '555-800-9000', '1979-05-08', '600-70-8000', 'D6007008', '717 Birch Wood Lane', 'San Antonio', 'TX', '78201', 'USA', '6600-6000-7000-8000', '6007008009', 'BRONZE'),
('STANDARD', 'EAST', 'Tyler', 'Clark', 'tclark@hotmail.com', '555-700-8000', '555-900-0001', '1988-09-22', '700-80-9000', 'D7008009', '828 Walnut Springs Road', 'Providence', 'RI', '02901', 'USA', '6700-7000-8000-9000', '7008009010', 'GOLD'),
('STANDARD', 'WEST', 'Kimberly', 'Ramirez', 'kramirez@outlook.com', '555-800-9000', '555-001-1112', '1995-12-04', '800-90-0001', 'D8009001', '939 Spruce Meadow Drive', 'Portland', 'OR', '97201', 'USA', '6800-8000-9000-0001', '8009010011', 'SILVER'),
('STANDARD', 'NORTH', 'Aaron', 'Lewis', 'alewis@gmail.com', '555-900-0001', '555-112-2223', '1982-03-17', '900-01-1112', 'D9010011', '150 Ash Park Boulevard', 'Columbus', 'OH', '43201', 'USA', '6900-9000-0001-1112', '9010011012', 'BRONZE'),
('STANDARD', 'SOUTH', 'Brittany', 'Robinson', 'brobinson@yahoo.com', '555-001-1112', '555-223-3334', '1991-07-29', '001-11-2223', 'D0111121', '261 Hickory Hollow Way', 'Charlotte', 'NC', '28201', 'USA', '7000-0001-1112-2223', '0111121213', 'PLATINUM'),
('STANDARD', 'EAST', 'Patrick', 'Walker', 'pwalker@gmail.com', '555-112-2223', '555-334-4445', '1974-11-11', '112-22-3334', 'D1122233', '372 Willow Bend Court', 'Buffalo', 'NY', '14201', 'USA', '7100-1112-2223-3334', '1122233344', 'GOLD'),
('STANDARD', 'WEST', 'Christina', 'Young', 'cyoung@hotmail.com', '555-223-3334', '555-445-5556', '1987-02-23', '223-33-4445', 'D2233344', '483 Poplar Heights Place', 'Las Vegas', 'NV', '89101', 'USA', '7200-2223-3334-4445', '2233344455', 'SILVER'),
('STANDARD', 'NORTH', 'Jonathan', 'Allen', 'jallen@outlook.com', '555-334-4445', '555-556-6667', '1993-06-15', '334-44-5556', 'D3344455', '594 Sycamore Valley Lane', 'Kansas City', 'MO', '64101', 'USA', '7300-3334-4445-5556', '3344455566', 'BRONZE'),
('STANDARD', 'SOUTH', 'Amber', 'King', 'aking@gmail.com', '555-445-5556', '555-667-7778', '1980-10-07', '445-55-6667', 'D4455566', '705 Magnolia Springs Road', 'Memphis', 'TN', '38101', 'USA', '7400-4445-5556-6667', '4455566677', 'GOLD'),
('STANDARD', 'EAST', 'Nathan', 'Wright', 'nwright@yahoo.com', '555-556-6667', '555-778-8889', '1996-01-19', '556-66-7778', 'D5566677', '816 Chestnut Creek Drive', 'Albany', 'NY', '12201', 'USA', '7500-5556-6667-7778', '5566677788', 'SILVER'),
('STANDARD', 'WEST', 'Victoria', 'Scott', 'vscott@gmail.com', '555-667-7778', '555-889-9990', '1984-05-02', '667-77-8889', 'D6677788', '927 Beech Grove Way', 'Seattle', 'WA', '98101', 'USA', '7600-6667-7778-8889', '6677788899', 'PLATINUM'),
('STANDARD', 'NORTH', 'Jacob', 'Torres', 'jtorres@hotmail.com', '555-778-8889', '555-990-0001', '1989-09-14', '778-88-9990', 'D7788899', '138 Locust Hill Court', 'St. Louis', 'MO', '63101', 'USA', '7700-7778-8889-9990', '7788899900', 'BRONZE'),
('STANDARD', 'SOUTH', 'Katherine', 'Nguyen', 'knguyen@outlook.com', '555-889-9990', '555-101-2020', '1977-12-26', '889-99-0001', 'D8899900', '249 Juniper Ridge Place', 'Austin', 'TX', '78701', 'USA', '7800-8889-9990-0001', '8899900011', 'GOLD'),
('STANDARD', 'EAST', 'Zachary', 'Hill', 'zhill@gmail.com', '555-990-0001', '555-202-3030', '1994-04-08', '990-00-1112', 'D9900011', '360 Cypress Creek Lane', 'Trenton', 'NJ', '08601', 'USA', '7900-9990-0001-1112', '9900011122', 'SILVER'),
('STANDARD', 'WEST', 'Danielle', 'Flores', 'dflores@yahoo.com', '555-101-2020', '555-303-4040', '1986-08-21', '101-20-2030', 'D1012020', '471 Oak Forest Road', 'Tucson', 'AZ', '85701', 'USA', '8000-0001-1112-2223', '0011122233', 'BRONZE'),
('STANDARD', 'NORTH', 'Eric', 'Green', 'egreen@gmail.com', '555-202-3030', '555-404-5050', '1991-11-03', '202-30-3040', 'D2023030', '582 Pine Mountain Drive', 'Omaha', 'NE', '68101', 'USA', '8100-1112-2223-3334', '1122233344', 'PLATINUM'),
('STANDARD', 'SOUTH', 'Melissa', 'Adams', 'madams@hotmail.com', '555-303-4040', '555-505-6060', '1978-03-16', '303-40-4050', 'D3034040', '693 Cedar Brook Way', 'Jacksonville', 'FL', '32099', 'USA', '8200-2223-3334-4445', '2233344455', 'GOLD'),
('STANDARD', 'EAST', 'Timothy', 'Nelson', 'tnelson@outlook.com', '555-404-5050', '555-606-7070', '1997-07-28', '404-50-5060', 'D4045050', '804 Maple Stream Court', 'Worcester', 'MA', '01601', 'USA', '8300-3334-4445-5556', '3344455566', 'SILVER'),
('STANDARD', 'WEST', 'Rebecca', 'Baker', 'rbaker@gmail.com', '555-505-6060', '555-707-8080', '1983-10-10', '505-60-6070', 'D5056060', '915 Elm Shade Place', 'Fresno', 'CA', '93701', 'USA', '8400-4445-5556-6667', '4455566677', 'BRONZE'),
('STANDARD', 'NORTH', 'Sean', 'Hall', 'shall@yahoo.com', '555-606-7070', '555-808-9090', '1990-02-22', '606-70-7080', 'D6067070', '126 Birch Valley Lane', 'Madison', 'WI', '53701', 'USA', '8500-5556-6667-7778', '5566677788', 'GOLD'),
('STANDARD', 'SOUTH', 'Laura', 'Rivera', 'lrivera@gmail.com', '555-707-8080', '555-909-0101', '1975-06-04', '707-80-8090', 'D7078080', '237 Walnut Grove Road', 'Nashville', 'TN', '37201', 'USA', '8600-6667-7778-8889', '6677788899', 'SILVER'),
('STANDARD', 'EAST', 'Adam', 'Campbell', 'acampbell@hotmail.com', '555-808-9090', '555-010-1212', '1998-09-16', '808-90-9010', 'D8089090', '348 Spruce Hill Drive', 'Wilmington', 'DE', '19801', 'USA', '8700-7778-8889-9990', '7788899900', 'PLATINUM'),
('STANDARD', 'WEST', 'Michelle', 'Mitchell', 'mmitchell@outlook.com', '555-909-0101', '555-121-2323', '1981-12-28', '909-01-0111', 'D9090101', '459 Ash Creek Way', 'Albuquerque', 'NM', '87101', 'USA', '8800-8889-9990-0001', '8899900011', 'BRONZE'),
('STANDARD', 'NORTH', 'Gregory', 'Carter', 'gcarter@gmail.com', '555-010-1212', '555-232-3434', '1988-04-09', '010-12-1222', 'D0101212', '570 Hickory Lake Court', 'Louisville', 'KY', '40201', 'USA', '8900-9990-0001-1112', '9900011122', 'GOLD'),
('STANDARD', 'SOUTH', 'Tiffany', 'Roberts', 'troberts@yahoo.com', '555-121-2323', '555-343-4545', '1993-08-21', '121-23-2333', 'D1212323', '681 Willow Point Place', 'Birmingham', 'AL', '35201', 'USA', '9000-0001-1112-2223', '0011122233', 'SILVER'),
('STANDARD', 'EAST', 'Derek', 'Gomez', 'dgomez@gmail.com', '555-232-3434', '555-454-5656', '1979-11-03', '232-34-3444', 'D2323434', '792 Poplar Ridge Lane', 'Hartford', 'CT', '06103', 'USA', '9100-1112-2223-3334', '1122233344', 'BRONZE'),
('STANDARD', 'WEST', 'Hannah', 'Phillips', 'hphillips@hotmail.com', '555-343-4545', '555-565-6767', '1995-03-15', '343-45-4555', 'D3434545', '903 Sycamore Bend Road', 'Reno', 'NV', '89501', 'USA', '9200-2223-3334-4445', '2233344455', 'PLATINUM'),
('STANDARD', 'NORTH', 'Scott', 'Evans', 'sevans@outlook.com', '555-454-5656', '555-676-7878', '1982-07-27', '454-56-5666', 'D4545656', '114 Magnolia Park Drive', 'Des Moines', 'IA', '50301', 'USA', '9300-3334-4445-5556', '3344455566', 'GOLD'),
('STANDARD', 'SOUTH', 'Angela', 'Turner', 'aturner@gmail.com', '555-565-6767', '555-787-8989', '1992-10-09', '565-67-6777', 'D5656767', '225 Chestnut Hill Way', 'Little Rock', 'AR', '72201', 'USA', '9400-4445-5556-6667', '4455566677', 'SILVER'),
('STANDARD', 'EAST', 'Mark', 'Diaz', 'mdiaz@yahoo.com', '555-676-7878', '555-898-9090', '1976-01-21', '676-78-7888', 'D6767878', '336 Beech Manor Court', 'Providence', 'RI', '02903', 'USA', '9500-5556-6667-7778', '5566677788', 'BRONZE'),
('STANDARD', 'WEST', 'Amy', 'Parker', 'aparker@gmail.com', '555-787-8989', '555-909-1010', '1987-05-03', '787-89-8999', 'D7878989', '447 Locust Springs Place', 'Salt Lake City', 'UT', '84101', 'USA', '9600-6667-7778-8889', '6677788899', 'GOLD'),
('STANDARD', 'NORTH', 'Jason', 'Cruz', 'jcruz@hotmail.com', '555-898-9090', '555-020-3131', '1994-08-15', '898-90-9000', 'D8989090', '558 Juniper Valley Lane', 'Sioux Falls', 'SD', '57101', 'USA', '9700-7778-8889-9990', '7788899900', 'SILVER'),
('STANDARD', 'SOUTH', 'Elizabeth', 'Edwards', 'eedwards@outlook.com', '555-909-1010', '555-131-4242', '1980-12-27', '909-10-1011', 'D9091010', '669 Cypress View Road', 'Baton Rouge', 'LA', '70801', 'USA', '9800-8889-9990-0001', '8899900011', 'PLATINUM'),

-- VIP Customers (25 records)
('VIP', 'NORTH', 'William', 'Collins', 'wcollins.vip@email.com', '555-111-0001', '555-222-0002', '1970-04-10', '111-00-0001', 'V1110001', '1 Executive Plaza', 'New York', 'NY', '10022', 'USA', '3711-1111-1111-1111', 'V1111111111', 'PLATINUM'),
('VIP', 'SOUTH', 'Elizabeth', 'Stewart', 'estewart.vip@email.com', '555-111-0002', '555-222-0003', '1968-08-22', '111-00-0002', 'V1110002', '2 Luxury Tower', 'Miami', 'FL', '33131', 'USA', '3711-2222-2222-2222', 'V2222222222', 'PLATINUM'),
('VIP', 'EAST', 'James', 'Sanchez', 'jsanchez.vip@email.com', '555-111-0003', '555-222-0004', '1972-12-05', '111-00-0003', 'V1110003', '3 Premium Heights', 'Boston', 'MA', '02110', 'USA', '3711-3333-3333-3333', 'V3333333333', 'PLATINUM'),
('VIP', 'WEST', 'Patricia', 'Morris', 'pmorris.vip@email.com', '555-111-0004', '555-222-0005', '1965-03-18', '111-00-0004', 'V1110004', '4 Elite Residence', 'Beverly Hills', 'CA', '90210', 'USA', '3711-4444-4444-4444', 'V4444444444', 'PLATINUM'),
('VIP', 'NORTH', 'Robert', 'Rogers', 'rrogers.vip@email.com', '555-111-0005', '555-222-0006', '1973-07-30', '111-00-0005', 'V1110005', '5 Distinguished Lane', 'Chicago', 'IL', '60611', 'USA', '3711-5555-5555-5555', 'V5555555555', 'PLATINUM'),
('VIP', 'SOUTH', 'Linda', 'Reed', 'lreed.vip@email.com', '555-111-0006', '555-222-0007', '1969-11-12', '111-00-0006', 'V1110006', '6 Prestige Boulevard', 'Dallas', 'TX', '75201', 'USA', '3711-6666-6666-6666', 'V6666666666', 'PLATINUM'),
('VIP', 'EAST', 'Charles', 'Cook', 'ccook.vip@email.com', '555-111-0007', '555-222-0008', '1971-02-24', '111-00-0007', 'V1110007', '7 Sovereign Circle', 'Washington', 'DC', '20001', 'USA', '3711-7777-7777-7777', 'V7777777777', 'PLATINUM'),
('VIP', 'WEST', 'Barbara', 'Morgan', 'bmorgan.vip@email.com', '555-111-0008', '555-222-0009', '1967-06-07', '111-00-0008', 'V1110008', '8 Imperial Court', 'San Francisco', 'CA', '94102', 'USA', '3711-8888-8888-8888', 'V8888888888', 'PLATINUM'),
('VIP', 'NORTH', 'Thomas', 'Bell', 'tbell.vip@email.com', '555-111-0009', '555-222-0010', '1974-10-19', '111-00-0009', 'V1110009', '9 Regal Estates', 'Philadelphia', 'PA', '19103', 'USA', '3711-9999-9999-9999', 'V9999999999', 'PLATINUM'),
('VIP', 'SOUTH', 'Susan', 'Murphy', 'smurphy.vip@email.com', '555-111-0010', '555-222-0011', '1966-01-31', '111-00-0010', 'V1110010', '10 Crown Heights', 'Atlanta', 'GA', '30303', 'USA', '3712-0000-0000-0000', 'V0000000000', 'PLATINUM'),
('VIP', 'EAST', 'Joseph', 'Bailey', 'jbailey.vip@email.com', '555-111-0011', '555-222-0012', '1970-05-13', '111-00-0011', 'V1110011', '11 Aristocrat Place', 'New York', 'NY', '10023', 'USA', '3712-1111-1111-1111', 'V1111111112', 'PLATINUM'),
('VIP', 'WEST', 'Jessica', 'Rivera', 'jrivera.vip@email.com', '555-111-0012', '555-222-0013', '1968-09-25', '111-00-0012', 'V1110012', '12 Opulent Way', 'Los Angeles', 'CA', '90024', 'USA', '3712-2222-2222-2222', 'V2222222223', 'PLATINUM'),
('VIP', 'NORTH', 'Richard', 'Cooper', 'rcooper.vip@email.com', '555-111-0013', '555-222-0014', '1972-12-07', '111-00-0013', 'V1110013', '13 Nobility Drive', 'Detroit', 'MI', '48226', 'USA', '3712-3333-3333-3333', 'V3333333334', 'PLATINUM'),
('VIP', 'SOUTH', 'Karen', 'Richardson', 'krichardson.vip@email.com', '555-111-0014', '555-222-0015', '1964-04-19', '111-00-0014', 'V1110014', '14 Grandeur Avenue', 'Houston', 'TX', '77002', 'USA', '3712-4444-4444-4444', 'V4444444445', 'PLATINUM'),
('VIP', 'EAST', 'Daniel', 'Cox', 'dcox.vip@email.com', '555-111-0015', '555-222-0016', '1975-08-01', '111-00-0015', 'V1110015', '15 Majesty Lane', 'Boston', 'MA', '02111', 'USA', '3712-5555-5555-5555', 'V5555555556', 'PLATINUM'),
('VIP', 'WEST', 'Nancy', 'Howard', 'nhoward.vip@email.com', '555-111-0016', '555-222-0017', '1969-11-13', '111-00-0016', 'V1110016', '16 Excellence Road', 'Seattle', 'WA', '98104', 'USA', '3712-6666-6666-6666', 'V6666666667', 'PLATINUM'),
('VIP', 'NORTH', 'Paul', 'Ward', 'pward.vip@email.com', '555-111-0017', '555-222-0018', '1971-03-26', '111-00-0017', 'V1110017', '17 Superior Street', 'Minneapolis', 'MN', '55402', 'USA', '3712-7777-7777-7777', 'V7777777778', 'PLATINUM'),
('VIP', 'SOUTH', 'Betty', 'Torres', 'btorres.vip@email.com', '555-111-0018', '555-222-0019', '1967-07-08', '111-00-0018', 'V1110018', '18 Paramount Circle', 'Phoenix', 'AZ', '85004', 'USA', '3712-8888-8888-8888', 'V8888888889', 'PLATINUM'),
('VIP', 'EAST', 'Steven', 'Peterson', 'speterson.vip@email.com', '555-111-0019', '555-222-0020', '1973-10-20', '111-00-0019', 'V1110019', '19 Distinction Court', 'Baltimore', 'MD', '21202', 'USA', '3712-9999-9999-9999', 'V9999999990', 'PLATINUM'),
('VIP', 'WEST', 'Dorothy', 'Gray', 'dgray.vip@email.com', '555-111-0020', '555-222-0021', '1965-02-02', '111-00-0020', 'V1110020', '20 Pinnacle Place', 'San Diego', 'CA', '92101', 'USA', '3713-0000-0000-0000', 'V0000000001', 'PLATINUM'),
('VIP', 'NORTH', 'George', 'Ramirez', 'gramirez.vip@email.com', '555-111-0021', '555-222-0022', '1970-06-14', '111-00-0021', 'V1110021', '21 Summit Estates', 'Cleveland', 'OH', '44114', 'USA', '3713-1111-1111-1111', 'V1111111113', 'PLATINUM'),
('VIP', 'SOUTH', 'Helen', 'James', 'hjames.vip@email.com', '555-111-0022', '555-222-0023', '1968-09-26', '111-00-0022', 'V1110022', '22 Apex Tower', 'Tampa', 'FL', '33602', 'USA', '3713-2222-2222-2222', 'V2222222224', 'PLATINUM'),
('VIP', 'EAST', 'Kenneth', 'Watson', 'kwatson.vip@email.com', '555-111-0023', '555-222-0024', '1972-01-08', '111-00-0023', 'V1110023', '23 Zenith Heights', 'Pittsburgh', 'PA', '15222', 'USA', '3713-3333-3333-3333', 'V3333333335', 'PLATINUM'),
('VIP', 'WEST', 'Sandra', 'Brooks', 'sbrooks.vip@email.com', '555-111-0024', '555-222-0025', '1966-05-20', '111-00-0024', 'V1110024', '24 Paramount Place', 'Portland', 'OR', '97204', 'USA', '3713-4444-4444-4444', 'V4444444446', 'PLATINUM'),
('VIP', 'NORTH', 'Edward', 'Kelly', 'ekelly.vip@email.com', '555-111-0025', '555-222-0026', '1974-08-02', '111-00-0025', 'V1110025', '25 Premier Lane', 'Columbus', 'OH', '43215', 'USA', '3713-5555-5555-5555', 'V5555555557', 'PLATINUM'),

-- INTERNAL Customers (15 records - employees/test accounts)
('INTERNAL', 'NORTH', 'Admin', 'User', 'admin@company.internal', '555-000-0001', '555-000-0002', '1980-01-01', '000-00-0001', 'I0000001', '100 Corporate HQ', 'New York', 'NY', '10001', 'USA', '0000-0000-0000-0001', 'I0000000001', 'INTERNAL'),
('INTERNAL', 'SOUTH', 'Test', 'Account', 'test@company.internal', '555-000-0003', '555-000-0004', '1980-01-02', '000-00-0002', 'I0000002', '100 Corporate HQ', 'Miami', 'FL', '33101', 'USA', '0000-0000-0000-0002', 'I0000000002', 'INTERNAL'),
('INTERNAL', 'EAST', 'QA', 'Engineer', 'qa@company.internal', '555-000-0005', '555-000-0006', '1980-01-03', '000-00-0003', 'I0000003', '100 Corporate HQ', 'Boston', 'MA', '02101', 'USA', '0000-0000-0000-0003', 'I0000000003', 'INTERNAL'),
('INTERNAL', 'WEST', 'Dev', 'Team', 'dev@company.internal', '555-000-0007', '555-000-0008', '1980-01-04', '000-00-0004', 'I0000004', '100 Corporate HQ', 'San Francisco', 'CA', '94102', 'USA', '0000-0000-0000-0004', 'I0000000004', 'INTERNAL'),
('INTERNAL', 'NORTH', 'Support', 'Staff', 'support@company.internal', '555-000-0009', '555-000-0010', '1980-01-05', '000-00-0005', 'I0000005', '100 Corporate HQ', 'Chicago', 'IL', '60601', 'USA', '0000-0000-0000-0005', 'I0000000005', 'INTERNAL'),
('INTERNAL', 'SOUTH', 'Sales', 'Demo', 'sales.demo@company.internal', '555-000-0011', '555-000-0012', '1980-01-06', '000-00-0006', 'I0000006', '100 Corporate HQ', 'Dallas', 'TX', '75201', 'USA', '0000-0000-0000-0006', 'I0000000006', 'INTERNAL'),
('INTERNAL', 'EAST', 'Marketing', 'Test', 'marketing.test@company.internal', '555-000-0013', '555-000-0014', '1980-01-07', '000-00-0007', 'I0000007', '100 Corporate HQ', 'Washington', 'DC', '20001', 'USA', '0000-0000-0000-0007', 'I0000000007', 'INTERNAL'),
('INTERNAL', 'WEST', 'Finance', 'System', 'finance@company.internal', '555-000-0015', '555-000-0016', '1980-01-08', '000-00-0008', 'I0000008', '100 Corporate HQ', 'Los Angeles', 'CA', '90001', 'USA', '0000-0000-0000-0008', 'I0000000008', 'INTERNAL'),
('INTERNAL', 'NORTH', 'HR', 'Portal', 'hr@company.internal', '555-000-0017', '555-000-0018', '1980-01-09', '000-00-0009', 'I0000009', '100 Corporate HQ', 'Philadelphia', 'PA', '19101', 'USA', '0000-0000-0000-0009', 'I0000000009', 'INTERNAL'),
('INTERNAL', 'SOUTH', 'Legal', 'Review', 'legal@company.internal', '555-000-0019', '555-000-0020', '1980-01-10', '000-00-0010', 'I0000010', '100 Corporate HQ', 'Atlanta', 'GA', '30301', 'USA', '0000-0000-0000-0010', 'I0000000010', 'INTERNAL'),
('INTERNAL', 'EAST', 'Compliance', 'Check', 'compliance@company.internal', '555-000-0021', '555-000-0022', '1980-01-11', '000-00-0011', 'I0000011', '100 Corporate HQ', 'Newark', 'NJ', '07101', 'USA', '0000-0000-0000-0011', 'I0000000011', 'INTERNAL'),
('INTERNAL', 'WEST', 'Security', 'Audit', 'security@company.internal', '555-000-0023', '555-000-0024', '1980-01-12', '000-00-0012', 'I0000012', '100 Corporate HQ', 'Seattle', 'WA', '98101', 'USA', '0000-0000-0000-0012', 'I0000000012', 'INTERNAL'),
('INTERNAL', 'NORTH', 'Ops', 'Monitor', 'ops@company.internal', '555-000-0025', '555-000-0026', '1980-01-13', '000-00-0013', 'I0000013', '100 Corporate HQ', 'Detroit', 'MI', '48201', 'USA', '0000-0000-0000-0013', 'I0000000013', 'INTERNAL'),
('INTERNAL', 'SOUTH', 'Data', 'Pipeline', 'data@company.internal', '555-000-0027', '555-000-0028', '1980-01-14', '000-00-0014', 'I0000014', '100 Corporate HQ', 'Houston', 'TX', '77001', 'USA', '0000-0000-0000-0014', 'I0000000014', 'INTERNAL'),
('INTERNAL', 'EAST', 'Integration', 'Service', 'integration@company.internal', '555-000-0029', '555-000-0030', '1980-01-15', '000-00-0015', 'I0000015', '100 Corporate HQ', 'Baltimore', 'MD', '21201', 'USA', '0000-0000-0000-0015', 'I0000000015', 'INTERNAL');

-- [step:verify]
-- Verify data load
SELECT
    CUSTOMER_TYPE,
    COUNT(*) as COUNT
FROM CUSTOMERS
GROUP BY CUSTOMER_TYPE
ORDER BY CUSTOMER_TYPE;

-- [step:classify]
-- ============================================================================
-- STEP 7: SENSITIVE DATA CLASSIFICATION
-- ============================================================================

-- Let Snowflake scan the table and detect PII automatically.
-- auto_tag = true applies the system tags SNOWFLAKE.CORE.SEMANTIC_CATEGORY
-- and SNOWFLAKE.CORE.PRIVACY_CATEGORY to every column it identifies.
CALL SYSTEM$CLASSIFY('<YOUR_DATABASE>.DEMODATASECURITY.CUSTOMERS', {'auto_tag': true});

-- Review which columns were tagged and how
SELECT COLUMN_NAME, TAG_NAME, TAG_VALUE
FROM TABLE(<YOUR_DATABASE>.INFORMATION_SCHEMA.TAG_REFERENCES_ALL_COLUMNS(
    '<YOUR_DATABASE>.DEMODATASECURITY.CUSTOMERS', 'table'))
WHERE TAG_NAME IN ('SEMANTIC_CATEGORY', 'PRIVACY_CATEGORY')
ORDER BY COLUMN_NAME, TAG_NAME;

-- [step:tags]
-- ============================================================================
-- STEP 8: CUSTOM TAGS AND TAG-BASED MASKING
-- ============================================================================

-- A custom sensitivity tag lets you govern columns by classification level
CREATE OR REPLACE TAG PII_LEVEL
    ALLOWED_VALUES 'HIGH', 'MEDIUM', 'LOW'
    COMMENT = 'Business sensitivity level for PII columns';

-- Generic string policy that will follow the tag, not a specific column
-- PII_ADMIN, PII_SUPPORT: Full value
-- Others: First character only (e.g. S***)
CREATE OR REPLACE MASKING POLICY mask_pii_tag AS (val STRING) RETURNS STRING ->
    CASE
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'PII_ADMIN', 'PII_SUPPORT') THEN val
        ELSE CONCAT(LEFT(val, 1), '***')
    END;

-- Attach the policy to the tag: any STRING column carrying PII_LEVEL is masked
ALTER TAG PII_LEVEL SET MASKING POLICY mask_pii_tag;

-- Tag columns that have no direct policy yet - they are now protected
ALTER TABLE CUSTOMERS MODIFY COLUMN LAST_NAME SET TAG PII_LEVEL = 'MEDIUM';
ALTER TABLE CUSTOMERS MODIFY COLUMN ZIP_CODE  SET TAG PII_LEVEL = 'LOW';

-- Tag the highly sensitive columns too (their direct policies take precedence)
ALTER TABLE CUSTOMERS MODIFY COLUMN SSN                SET TAG PII_LEVEL = 'HIGH';
ALTER TABLE CUSTOMERS MODIFY COLUMN CREDIT_CARD_NUMBER SET TAG PII_LEVEL = 'HIGH';
ALTER TABLE CUSTOMERS MODIFY COLUMN BANK_ACCOUNT       SET TAG PII_LEVEL = 'HIGH';

-- [step:view]
-- ============================================================================
-- STEP 9: ROLE-BASED VIEW
-- ============================================================================

-- A secure view exposes only the columns Marketing needs.
-- Masking and row access policies on the base table still apply through it.
CREATE OR REPLACE SECURE VIEW CUSTOMERS_MARKETING_V AS
SELECT CUSTOMER_ID, CUSTOMER_TYPE, REGION, FIRST_NAME, LAST_NAME, EMAIL,
       CITY, STATE, ZIP_CODE, MEMBERSHIP_LEVEL
FROM CUSTOMERS;

GRANT SELECT ON VIEW CUSTOMERS_MARKETING_V TO ROLE PII_MARKETING;

-- In production you would also remove direct table access:
-- REVOKE SELECT ON TABLE CUSTOMERS FROM ROLE PII_MARKETING;

-- [step:testing]
-- ============================================================================
-- STEP 10: ROLE TESTING - Run as each role and compare results
-- ============================================================================

-- DEMO 1: PII_ADMIN - Full access to all data
USE ROLE PII_ADMIN;
SELECT CUSTOMER_ID, CUSTOMER_TYPE, FIRST_NAME, LAST_NAME, EMAIL, PHONE_NUMBER,
       DATE_OF_BIRTH, SSN, CREDIT_CARD_NUMBER, STREET_ADDRESS, CITY, STATE, ZIP_CODE
FROM <YOUR_DATABASE>.DEMODATASECURITY.CUSTOMERS
WHERE CUSTOMER_ID = 1;

-- DEMO 2: PII_ANALYST - Partial masking, all rows
USE ROLE PII_ANALYST;
SELECT CUSTOMER_ID, CUSTOMER_TYPE, FIRST_NAME, LAST_NAME, EMAIL, PHONE_NUMBER,
       DATE_OF_BIRTH, SSN, CREDIT_CARD_NUMBER, STREET_ADDRESS, CITY, STATE, ZIP_CODE
FROM <YOUR_DATABASE>.DEMODATASECURITY.CUSTOMERS
WHERE CUSTOMER_ID = 1;

-- DEMO 3: PII_SUPPORT - Full contact info, STANDARD customers only
USE ROLE PII_SUPPORT;
SELECT CUSTOMER_ID, CUSTOMER_TYPE, FIRST_NAME, LAST_NAME, EMAIL, PHONE_NUMBER,
       DATE_OF_BIRTH, SSN, CREDIT_CARD_NUMBER, STREET_ADDRESS, CITY, STATE, ZIP_CODE
FROM <YOUR_DATABASE>.DEMODATASECURITY.CUSTOMERS
WHERE CUSTOMER_ID = 1;

-- DEMO 4: PII_MARKETING - Limited data, no INTERNAL customers
USE ROLE PII_MARKETING;
SELECT * FROM <YOUR_DATABASE>.DEMODATASECURITY.CUSTOMERS_MARKETING_V
WHERE CUSTOMER_ID = 1;

-- DEMO 5: Row count comparison across roles
USE ROLE PII_ADMIN;
SELECT 'PII_ADMIN' AS ROLE, COUNT(*) AS VISIBLE_ROWS FROM <YOUR_DATABASE>.DEMODATASECURITY.CUSTOMERS;      -- Expected: 98

USE ROLE PII_ANALYST;
SELECT 'PII_ANALYST' AS ROLE, COUNT(*) AS VISIBLE_ROWS FROM <YOUR_DATABASE>.DEMODATASECURITY.CUSTOMERS;    -- Expected: 98

USE ROLE PII_SUPPORT;
SELECT 'PII_SUPPORT' AS ROLE, COUNT(*) AS VISIBLE_ROWS FROM <YOUR_DATABASE>.DEMODATASECURITY.CUSTOMERS;    -- Expected: 58 (STANDARD only)

USE ROLE PII_MARKETING;
SELECT 'PII_MARKETING' AS ROLE, COUNT(*) AS VISIBLE_ROWS FROM <YOUR_DATABASE>.DEMODATASECURITY.CUSTOMERS;  -- Expected: 83 (STANDARD + VIP)

USE ROLE ACCOUNTADMIN;

-- [step:cleanup]
-- ============================================================================
-- STEP 11: CLEANUP (Optional - uncomment to remove demo objects)
-- ============================================================================

-- USE ROLE ACCOUNTADMIN;
-- ALTER TAG <YOUR_DATABASE>.DEMODATASECURITY.PII_LEVEL UNSET MASKING POLICY mask_pii_tag;
-- DROP SCHEMA IF EXISTS <YOUR_DATABASE>.DEMODATASECURITY CASCADE;  -- drops table, view, policies and tag
-- DROP ROLE IF EXISTS PII_ADMIN;
-- DROP ROLE IF EXISTS PII_ANALYST;
-- DROP ROLE IF EXISTS PII_SUPPORT;
-- DROP ROLE IF EXISTS PII_MARKETING;
