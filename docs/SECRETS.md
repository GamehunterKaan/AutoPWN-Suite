# Secrets and credential management

The owner listed in [GOVERNANCE.md](../GOVERNANCE.md) controls project credentials
and maintains the access inventory. Review access before any elevation, at least
quarterly, on role changes, and immediately after a suspected compromise.

## Storage and access

- Store Docker Hub publishing credentials only in GitHub Actions encrypted
  repository/environment secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`.
  Use a repository-scoped publishing token where the provider supports it.
  Only the isolated push/sign jobs reference these secrets; PR scans/tests and
  image builds receive none. GitHub job tokens are short-lived with explicit
  minimum permissions. OIDC signs releases without a stored signing key, and the
  PyPI package is published through trusted publishing, so no PyPI token or
  password exists in the repository or its settings; never create one. The
  OpenSSF Scorecard workflow publishes its results with its OIDC token; the
  optional personal access token its template offers (`SCORECARD_TOKEN`) is not
  configured and must not be added.
- Never commit secrets, recovery codes, private keys, `.env` values, scanner
  configuration or credential-bearing scan evidence. Secret scanning and push
  protection are enabled on the authoritative repository. Do not bypass an alert
  for a genuine credential. Exclude local secrets from Docker build contexts.
- Runtime NVD keys, SMTP passwords and webhook URLs are operator-owned secrets.
  The current dashboard stores values entered in its settings page in
  **unencrypted** `web_ui_settings.json`; CLI/daemon configuration and optional
  `api.txt` are also plaintext. `--create-config` and `--daemon-install` create the
  INI file with mode `0600`, and the daemon installer creates the installed
  `/opt/autopwn-suite/autopwn-daemon.conf` owner-only from its first byte too,
  replacing, not rewriting, a copy that an earlier release left readable (Windows has no POSIX
  modes) and `--daemon-uninstall` deletes that installed copy; a configuration file or `api.txt` you write yourself keeps whatever mode
  you give it. Since v2.6.1, credential files are supported:
  `AUTOPWN_NIST_API_KEY_FILE`, `AUTOPWN_SMTP_PASSWORD_FILE` and
  `AUTOPWN_WEBHOOK_URL_FILE` each name a file holding exactly one non-empty
  UTF-8 line of at most 4096 bytes (a leading byte order mark and the line ending
  are not part of the secret). The CLI and dashboard read them at use time,
  so a rotated secret takes effect without a restart. The dashboard overlays them
  on the stored settings and never writes them into `web_ui_settings.json`, but a
  value an operator also typed into settings stays stored in plaintext. Keep each
  file owner-only (mode `0600`, or a mounted container secret); the application
  does not check the file's permissions and reports a bad file without printing its
  contents. Use a
  dedicated scanner account, an absolute `AUTOPWN_DATA_DIR` outside the checkout,
  directory mode `0700` and file mode `0600` (or equivalent owner-only Windows
  ACLs). The dashboard writes its settings, profiles, schedules and account files
  with mode `0600` on POSIX (it restricts a file that an earlier release left readable
  by others when it starts, and logs one line when it does) and creates a missing data directory with mode `0700`,
  but it does not change the mode of an existing directory or of any other file,
  and it does not encrypt these files.
  Use host/disk encryption and encrypted, access-controlled backups. Protect
  caller-CWD configuration, exports, logs and downloaded evidence separately:
  `AUTOPWN_DATA_DIR` does not relocate every file.
- Restrict dashboard ingress to authorized operators with the default loopback
  bind or a firewall/VPN, and use HTTPS for any remote access. v2.6.0 has no
  login. Since v2.6.1 the dashboard requires sign-in as a single administrator account
  whose username and scrypt password hash are stored in `web_ui_auth.json`
  (generated random password shown once at first launch; change it in Settings
  or regenerate it with `--web-reset-account`). Treat that file like the other
  dashboard files: owner-only storage and encrypted backups. It is one shared
  account without MFA, and the password is not recoverable, only resettable on
  the server. Settings APIs can still expose stored integration values to a
  signed-in client; host-file permissions alone do not protect the API. Do not
  share the scanner account with unrelated applications or credentials.
- Do not print secrets in Actions output, reports, screenshots, issue bodies or
  command-line arguments. Masking is a backup control, not permission to log
  secrets. Notification failures therefore log the error class and HTTP status, not
  the exception text, which can quote a webhook URL. Review and redact evidence before sharing it. Store MFA recovery codes
  in the owner's password manager, outside the repository and CI.

## Rotation, revocation and incidents

Rotate long-lived project publishing credentials at least every **90 days**, on
access removal, or immediately after exposure, suspicious use or provider alert.
Prefer provider-issued expiring tokens. Record credential reference/provider,
owner, scope, creation/expiry and last rotation in the owner's private password
manager; the public inventory contains references only. Runtime operators should
apply the same schedule to integrations, subject to provider capabilities.

Create a replacement with the minimum scope, update the secret through the
provider/GitHub secret settings, validate a permitted operation, then revoke the
old credential. If compromised, revoke first and recover through the provider.
Remove departed users' permissions, active sessions, tokens and recovery access;
rotate any shared credentials they could read. Check Actions, provider and
repository audit trails for misuse, stop affected publication, and verify release
digests before restoring it. Coordinate user notification through
[SECURITY.md](../SECURITY.md). Deleting a Git commit does not revoke an exposed
credential; rotation and investigation are mandatory even after history cleanup.

This is the required management policy. A document does not establish that old
credentials have already been rotated or that host ACLs have been audited.
