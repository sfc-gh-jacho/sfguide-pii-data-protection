# Protecting PII in Snowflake

**Owner:** Janet Cho · **Last reviewed:** November 2026 · **License:** [Apache 2.0](LICENSE)

A customer-facing, step-by-step guide to protecting personally identifiable information (PII) with Snowflake Horizon governance features:

- **Sensitive Data Classification**: automatically discover PII columns and apply system tags
- **Object Tagging and Tag-based Masking**: attach one masking policy to a tag so it protects every tagged column
- **Dynamic Data Masking**: column-level policies that return full, partial or masked values by role
- **Row Access Policies**: row-level filtering by role
- **Role-based Secure Views**: purpose-built, least-privilege slices of a table

**Live guide:** https://sfc-gh-jacho.github.io/sfguide-pii-data-protection/

The site is fully static. It does not connect to any Snowflake account. You copy the SQL and run it in your own account.

## Prerequisites

- **Snowflake Enterprise Edition or higher** (required for masking, row access, tag-based masking and classification)
- A warehouse (any size works) and an existing database for the demo schema
- **A role to run it.** ACCOUNTADMIN is simplest in a sandbox. For regulated environments, use the least-privilege option below.

### Least-privilege option (no ACCOUNTADMIN)

The script starts with `SET demo_role = 'ACCOUNTADMIN';`. To run without ACCOUNTADMIN, an administrator runs the commented block at the top of Step 1 once:

```sql
USE ROLE ACCOUNTADMIN;
CREATE ROLE IF NOT EXISTS PII_DEMO_ROLE;
GRANT USAGE ON DATABASE <YOUR_DATABASE> TO ROLE PII_DEMO_ROLE WITH GRANT OPTION;   -- passed on to the 4 demo roles
GRANT CREATE SCHEMA ON DATABASE <YOUR_DATABASE> TO ROLE PII_DEMO_ROLE;
GRANT USAGE ON WAREHOUSE <YOUR_WAREHOUSE> TO ROLE PII_DEMO_ROLE WITH GRANT OPTION;
GRANT CREATE ROLE ON ACCOUNT TO ROLE PII_DEMO_ROLE;                             -- PII_ADMIN / ANALYST / SUPPORT / MARKETING
GRANT APPLY MASKING POLICY ON ACCOUNT TO ROLE PII_DEMO_ROLE;                    -- tag-based masking (Step 8)
GRANT ROLE PII_DEMO_ROLE TO USER <YOUR_USER>;
```

Then change the first line to `SET demo_role = 'PII_DEMO_ROLE';`. The role owns the demo schema and everything in it, so it can create and apply the masking and row access policies and run classification without further grants. The masking policies treat it like ACCOUNTADMIN (full values), and the four demo roles are granted to it. This path was tested end to end and produced identical results.

## Run the demo in Snowsight

1. Download [`sql/pii_demo_setup.sql`](sql/pii_demo_setup.sql).
2. In Snowsight, open **Projects → Worksheets** and create a new SQL worksheet.
3. Paste the script and use find-and-replace on these placeholders:
   | Placeholder | Replace with |
   |---|---|
   | `<YOUR_WAREHOUSE>` | a warehouse you can use, e.g. `COMPUTE_WH` |
   | `<YOUR_DATABASE>` | an existing database for the demo schema |
4. Run Steps 1–9 in order (or **Run All**). Step 10 switches between the demo roles so you can compare results.
5. When you're done, uncomment and run Step 11 (Cleanup).

## What gets created

| Object | Name |
|---|---|
| Schema | `DEMODATASECURITY` |
| Table | `CUSTOMERS` (98 synthetic rows: 58 STANDARD, 25 VIP, 15 INTERNAL) |
| Roles | `PII_ADMIN`, `PII_ANALYST`, `PII_SUPPORT`, `PII_MARKETING` |
| Masking policies | `mask_ssn`, `mask_dob`, `mask_phone`, `mask_email`, `mask_credit_card`, `mask_address`, `mask_bank_account`, `mask_drivers_license`, `mask_pii_tag` |
| Row access policy | `customer_row_access` |
| Tag | `PII_LEVEL` (HIGH / MEDIUM / LOW) |
| Secure view | `CUSTOMERS_MARKETING_V` |

## Repository layout

```
LICENSE                    Apache License 2.0
vendor/prism/              Prism.js (MIT), served locally
index.html                 Single-page guide
styles.css                 Styling (Snowflake palette)
script.js                  Loads SQL steps, Prism highlighting, copy buttons, results tables
sql/pii_demo_setup.sql     Full demo script (split into steps by "-- [step:<id>]" markers)
data/sample_results.json   Expected per-role results, computed from the script's sample data
```

To preview locally, serve the folder over HTTP (the page fetches the SQL and JSON files):

```
python3 -m http.server 8000
```

## Customize with Cortex Code

[Cortex Code](https://docs.snowflake.com/en/user-guide/cortex-code/cortex-code) can adapt this guide to your own data. Open the repo folder in Cortex Code and try prompts like:

- "Point this demo at my customer table: map its columns to CUSTOMERS, run classification, and propose masking policies for each detected category before applying anything."
- "Replace the hard-coded role lists in the masking policies with a mapping table so I can add roles without editing policies."
- "Add a row access policy that restricts my analysts to their own region using my existing role hierarchy, and show the before and after row counts."

Ask it to review the plan with you before it creates or changes any objects in your account.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Prism.js, used for syntax highlighting, is bundled in `vendor/prism/` under its own MIT license, so the pages make no third-party requests.

## Disclaimer

All data in this repository is synthetic and was generated for demonstration only. Phone numbers use the fictional 555 prefix, and SSNs, card and account numbers are sequential or test patterns. No real people are represented. The repository contains no credentials, account identifiers or connection details.
