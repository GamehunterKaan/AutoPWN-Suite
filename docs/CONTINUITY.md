# Access continuity and bus factor

AutoPWN Suite has an owner and, per the owner's attestation, a second maintainer
account (see [GOVERNANCE.md](../GOVERNANCE.md)). This document defines how issue
handling, change acceptance and releases can continue **within one week** if the
owner is suddenly unavailable (illness, loss of account access, death or
abandonment), and what would make the project's bus factor verifiable. It describes
policy and procedure; the status table below says exactly what is attested and what
is not recorded.

## Honest bus-factor statement

- **Bus factor: 2, per the owner's attestation of 2026-10-16.** The owner states that a
  second maintainer account (<https://github.com/autosec-overflow>) holds the GitHub,
  Docker Hub and DNS successor arrangements. The repository confirms only that this
  account has **write** access to the repository (admin is not granted); the rest is
  the owner's statement and cannot be verified from the repository.
- Git history is almost entirely the owner's commits (under two names) plus Dependabot;
  since 2025-10-01 no other human has authored a commit. Earlier contributors (for
  example `iaacornus`, last commit April 2024) hold no recorded sensitive access.
- Documentation cannot establish a bus factor by itself. The list below is the
  checklist for making the second maintainer's access visible and tested.

### Making bus factor 2 verifiable

1. Identify a trusted contributor or maintainer and complete the identity,
   history, MFA/passkey and task review in
   [GOVERNANCE.md](../GOVERNANCE.md#review-before-granting-sensitive-access).
2. Grant that person repository **admin** (or at least maintain with the ability to
   approve pull requests and run release workflows), private-advisory access, and
   a way to publish to the Docker Hub repository `gamehunterkaan/autopwn-suite`.
3. Record the person, role and review date in the public access inventory in
   GOVERNANCE.md and confirm that they can complete a dry-run of the
   [release procedure](RELEASING.md) and verification steps.
4. Have the second person approve at least one pull request and take part in one
   release, so the process is practiced and not only written.

## Resources a successor needs

| Resource | Why it matters | How continuity works |
| --- | --- | --- |
| GitHub repository `GamehunterKaan/AutoPWN-Suite` (user-owned repository) | Source, issues, pull requests, branch protection, Actions settings, security advisories, releases. | Needs a second **admin collaborator**, or GitHub's account-successor designation for the owner's personal account, or a repository transfer to an organization with at least two owners. Branch protection must keep requiring checks and non-author human review for the successor too. |
| GitHub Actions secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` | Only the isolated image push job uses them ([secret policy](SECRETS.md)). | Secrets values cannot be read back from GitHub. The successor replaces them: create a new scoped Docker Hub access token, store it in the repository secrets, run a permitted operation, then revoke the old token ([rotation procedure](SECRETS.md#rotation-revocation-and-incidents)). |
| Docker Hub account / repository `gamehunterkaan/autopwn-suite` | Distribution channel for the container image. | Successor needs Docker Hub access to the repository (collaborator or organization membership) or access to the namespace owner account through the arrangements below. A future move of the repository to a Docker Hub organization with more than one owner would remove this single point of failure. |
| Release signing identity | Releases are signed with Sigstore **keyless** signing from the GitHub Actions workflow identity and GitHub OIDC. **No long-lived private signing key exists**, so there is no key to escrow or lose. | Any repository admin can run the release workflows from `main` and signatures bind to that workflow identity. If the repository is renamed or transferred, the expected signer identity in [consumer verification](RELEASING.md) changes; update those commands and note it in the release notes. |
| Project homepage and domain `kaangultekin.net` | Linked from the README and the dashboard; it is not required to build, test or release the software. | The repository and its documentation remain authoritative without the site ([architecture](ARCHITECTURE.md)). A successor needs the registrar/DNS and hosting credentials to change or retire the site; if unavailable, update README links to point to the repository. |
| PyPI | No PyPI publication is documented for this project ([building](BUILDING.md)); installs are from source or the container image. | Nothing to transfer today. If a PyPI project is added, list its owners here and require at least two. |
| Private security-advisory channel | Receives vulnerability reports ([SECURITY.md](../SECURITY.md)). | Repository admins and security managers can read advisories. The successor must be added before they are needed. |
| Owner's MFA/passkey and recovery codes | Needed to recover owner accounts. | Held in the owner's password manager, never in the repository ([secret policy](SECRETS.md)); see the escrow procedure below. |

## Succession and escrow procedure

The owner maintains these arrangements privately; this repository must not contain
passwords, tokens, recovery codes or private contact details.

1. **Designated backup maintainer.** The owner names one backup in the GOVERNANCE.md
   access inventory once the access review is complete. The backup holds real
   permissions (admin collaborator, private advisories) in advance, so activation
   needs no action from the owner.
2. **Emergency access for credentials.** The owner configures a password-manager
   emergency-access feature (or equivalent) that lets a trusted person request
   access to the vault after a waiting period, **or** keeps a sealed envelope with a
   trusted person or a lawyer containing instructions and the recovery material for
   the GitHub account, Docker Hub account, domain registrar and password manager.
   Use a waiting period short enough that access is available within one week.
3. **Account-level succession.** The owner designates a GitHub account successor
   for the personal account and keeps the list of provider-specific succession
   options (Docker Hub, registrar) in the private vault.
4. **Review.** The owner reviews the backup, emergency-access recipient, envelope
   holder and these procedures at least quarterly with the access review required by
   [GOVERNANCE.md](../GOVERNANCE.md) and after any change of person or account.
5. **After activation.** The successor rotates every credential they could read
   ([secret policy](SECRETS.md)), checks the Actions, Docker Hub and repository audit
   trails, updates the access inventory, and notes the change in the repository
   so the public record stays accurate.

## Doing the work within one week

A successor who holds the access above can keep the project running as follows.

| Task | Steps and expected timing |
| --- | --- |
| **Day 1: take stock** | Confirm admin access to the repository; check open security advisories and private reports first and acknowledge them within the targets in [SECURITY.md](../SECURITY.md); check recent Actions runs and Dependabot pull requests. |
| **Issues and support** | Triage new issues as described in [SUPPORT.md](../SUPPORT.md); respond to or close stale issues; keep the support lifecycle statement accurate. |
| **Accepting changes** | Reviews and merges follow the normal rules: pull requests, required checks and at least one **non-author human approval** ([GOVERNANCE.md](../GOVERNANCE.md)). A sole successor cannot approve their own changes, so they need a second human reviewer (the backup maintainer or a trusted contributor) or must first recruit one. Do not bypass protection. Dependabot, bots and AI reviewers do not count. Merging within the week is therefore possible for **externally authored** pull requests, which a single successor can approve. |
| **Security releases** | Follow the [release procedure](RELEASING.md): update versions and changelog, merge through protected `main`, tag reviewed history, publish the GitHub release, let the workflows build, sign and verify, then independently verify the signatures as documented. This can be completed in about one day when CI is healthy. |
| **Credentials** | If Docker Hub credentials are unavailable, rotate them as described above before the next image publication. Nothing else in the release path depends on a stored secret. |
| **Communication** | Post a short notice in the repository (issue or discussion) that maintainership continues, and update GOVERNANCE.md. |

If **no** successor can be reached within one week, GitHub support procedures for
account recovery or transfer of an abandoned repository are the fallback. Because the
source is Apache-2.0 licensed, anyone may also fork the project; a fork has a new
repository identity, so its releases would carry a different Sigstore signer
identity from official releases.

## Status of arrangements

The repository records only what the owner has attested. The owner updates this
table (with dates, but no secret details) as each arrangement is put in place. Items
marked "Not recorded" or "Not configured" have **not** been done; they are not
assumed.

| Arrangement | Status |
| --- | --- |
| Second maintainer or designated backup | Per the owner's attestation of 2026-10-16: an account with repository write access (admin not granted); details held privately |
| Second human reviewer able to approve owner-authored changes | Not configured |
| GitHub account successor designation | In place per the owner's attestation of 2026-10-16; the person and mechanism are intentionally not recorded in the repository |
| Password-manager emergency access or sealed-envelope escrow | Not recorded |
| Docker Hub access for a second person, or a move to a multi-owner organization | In place per the owner's attestation of 2026-10-16; details held privately |
| Registrar/DNS access plan for `kaangultekin.net` | In place per the owner's attestation of 2026-10-16; details held privately |
| Last continuity review | Not yet performed |
