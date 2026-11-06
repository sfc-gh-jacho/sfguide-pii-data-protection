# Protecting PII in Snowflake

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
- **ACCOUNTADMIN**, or a custom role with:
  - `CREATE ROLE` on the account
  - `USAGE` on a database and `CREATE SCHEMA` on it
  - `APPLY MASKING POLICY`, `APPLY ROW ACCESS POLICY` and `APPLY TAG` on the account
  - `USAGE` on a warehouse, plus the ability to grant it to the demo roles
- A warehouse (any size works)

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

## Disclaimer

All data in this repository is synthetic and was generated for demonstration only. Phone numbers use the fictional 555 prefix, and SSNs, card and account numbers are sequential or test patterns. No real people are represented. The repository contains no credentials, account identifiers or connection details.
