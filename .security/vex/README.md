# Public non-exploitability feed

[index.json](index.json) lists published OpenVEX 0.2.0 documents. The feed is
currently empty: the dependency audit found no advisory requiring a not-affected
declaration. An empty index is **not** an OpenVEX document and does not assert
that the product is free of vulnerabilities. Existing product findings are in
the [advisory index](../../docs/SECURITY_ADVISORIES.md).

When a dependency advisory is determined not to affect AutoPWN Suite, add a
`NAME.openvex.json` document to this directory and its filename to the index.
Use the [OpenVEX schema](https://github.com/openvex/spec/blob/main/openvex_json_schema.json),
a stable HTTPS document ID, author, timestamp and increasing document version.
Every not-affected statement must include:

- The real vulnerability ID and relevant aliases; never invent identifiers.
- An exact product `@id`, for example
  `pkg:github/GamehunterKaan/AutoPWN-Suite@2.7.0`, and an exact versioned component
  purl under that product's `subcomponents`.
- `status: not_affected`, an OpenVEX justification, a substantive
  `impact_statement`, and `status_notes` citing the reviewed call path,
  configuration and independent review/issue evidence.
- An assessment timestamp no more than 90 days old. Reassess for each product or
  dependency version change and whenever assumptions change. Publish affected
  or under-investigation updates when non-exploitability no longer holds.

An independent human must review each declaration before merging. Only current,
exact matching statements can suppress SCA findings; affected, fixed,
under-investigation and unmatched statements do not suppress. Known malicious
packages cannot be suppressed. Unsupported assumptions and pending fixes do not
justify `not_affected`. The release pipeline attaches a versioned feed snapshot
and any documents and includes their hashes in the signed manifest.
