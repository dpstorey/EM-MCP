---
name: tenable-ot-analysis-reporting
description: Use when summarising Tenable OT assets, interpreting RAISE values, producing asset intelligence analysis, or generating a self-contained HTML report from retrieved tot-mcp data.
---

# Tenable OT Analysis and Reporting

Use only data returned by the current `tot-mcp` session. Follow the Tenable OT Operations skill for ICP selection, querying, limits, confirmation, and data integrity.

Produce only the deliverable the user requested. Do not automatically chain a table, detailed profile, and report together.

## Asset summary

For a requested asset summary, use this column order:

| Asset | IP Address | Asset Type | Numerical Risk Score | Description | R | A | I | S | E |
|---|---|---|---:|---|:---:|:---:|:---:|:---:|:---:|

Map fields as follows:

- **Asset:** `name`
- **IP Address:** `ips`
- **Asset Type:** `type`
- **Numerical Risk Score:** `risk.total_risk`, rounded to one decimal place
- **Description:** `description`; use `-` when missing
- **R, A, I, S, E:** corresponding values from `custom_fields`

Only display RAISE letters `A`, `B`, `C`, `D`, or `E`. Display `-` for missing or invalid values.

## RAISE analysis

Use `references/raise-risk-table.md` as the authoritative source for all RAISE descriptions. Never recreate or modify the definitions.

Process categories only in this order: **R, A, I, S, E**.

Rules:

1. Accept only `A` through `E` as valid values.
2. Convert missing, empty, or invalid values to `-`.
3. Never infer a missing value.
4. Generate RAISE analysis only when at least one valid value exists.

### RAISE section in an asset profile

Use this structure:

**Section B: RAISE Risk Detail**

| Risk | Value | Description |
|---|:---:|---|

- Add rows in R, A, I, S, E order.
- Include only categories with valid values.
- Copy the matching official description from the reference file.
- Omit Section B entirely when no valid value exists.

### Standalone RAISE summary

Use this compact layout:

| R | A | I | S | E |
|:---:|:---:|:---:|:---:|:---:|

Render invalid or absent values as `-`. When the user asks for explanations, add the official descriptions below the compact table.

## HTML report workflow

Use this workflow only when the user explicitly asks for a report, document, HTML file, or downloadable artifact.

## MANDATORY REPORT HEADER

Every generated HTML report MUST include the Tenable OT banner header.

The header MUST:
- Be the first visible content in the HTML body.
- Use the image from /llm-scratch/00-resources/trh2.png.
- Embed the image using a Base64 data URI.
- Be rendered at a width of 1400px to match the report layout.
- Align with the report body width.
- Appear at the top of every report without exception.

The report is considered INVALID if:
- The banner header is missing.
- The banner is not the first visible element.
- The banner is not rendered at 1400px width.

The model MUST verify the presence of:

<img class="banner" src="data:image/png;base64,...">

before considering report generation complete.

### Scope and missing assets

1. Use the ICP selected in the current session. Do not silently force the London ICP unless the user explicitly requested London.
2. For one requested asset, create one asset report.
3. For multiple requested assets, create one consolidated report.
4. If any requested asset is not found:
   - List the missing asset names.
   - Do not substitute similar assets.
   - Ask whether to continue with the assets found or cancel.
   - Stop until the user answers.

### Gather report data

Retrieve available, relevant data for:

- Asset details
- RAISE custom fields
- Vulnerabilities
- Up to 10 recent events, ordered by severity
- One-hop communication peers
- Attack pathways, when available

Do not invent absent sections. Mark unavailable data clearly.

### Build the file

1. Use `workspace-shell` MCP for filesystem operations.
2. Put temporary files and Python scripts under `/llm-scratch/tmp`.
3. Create `/llm-scratch/tmp/generate_report.py` to construct the report.
4. Run `python3 /llm-scratch/tmp/generate_report.py`.
5. Check stdout, stderr, and exit status. Stop and report the error if execution fails.
6. Read the banner image from `/llm-scratch/00-resources/trh2.png`.
7. Base64-encode the image in Python and embed it as:
   `<img class="banner" src="data:image/png;base64,{banner_b64}" />`
8. Build a completely self-contained HTML document with inline CSS and no external dependencies.
9  Append a UTC datestamp to the filename using the format:

     <filename>-YYYYMMDD-HHMMSSZ

   Example:

     REACTOR_10.253.10.244_Report-20260716-224531Z.html

   Where:
     - YYYYMMDD is the UTC date.
     - HHMMSS is the UTC time.
     - The trailing Z indicates UTC.
10. The final file MUST be written to directory `/llm-scratch/20-reports/`.
11. Make the completed HTML file available through a LibreChat artifact.

### Verify the report

Before presenting it, verify all of the following:

- The final file exists.
- Its size exceeds 10 KB.
- It contains `data:image/png;base64,`.
- It contains no external image, stylesheet, script, font, or other network reference.

Stop and report the failed check if any verification fails.

### Report content

Include sections when supporting data exists:

- Asset details: type, vendor, model, firmware, criticality, run status, and location
- RAISE summary
- Appendix A: full official RAISE matrix
- Vulnerability summary: CVSS, KEV status, and evidence-based mitigation guidance
- Top 10 events
- One-hop communication paths
- Attack pathways
- Analyst assessment and prioritised recommendations

Recommendations must be supported by retrieved evidence and must distinguish fact from analyst judgement.

### Report styling

Use:

- Yellow: `#ECFF53`
- Black: `#192224`
- White: `#FFFFFF`
- Page background: black
- Main text: white
- Primary highlights: yellow text
- Secondary highlights: black text on a yellow background
- Table borders: yellow
- Table headers: yellow background with black text

Do not place a separator line directly below the banner.
