# Image advisory triage (v2.6.0 container image)

Triaged 2026-10-16 for the OpenSSF `dependency_monitoring` criterion. This is a
**human-readable triage record, not a set of VEX statements**. Nothing here suppresses
a finding: the project's [security policy](SECURITY_TESTING.md) accepts only reviewed,
exact OpenVEX documents in [`.security/vex`](../.security/vex/README.md) for that, and no such
document has been created.

## Scope and sources

- **Subject:** the signed SCA report for the released image, `autopwn-suite-v2.6.0-linux-amd64-sca.json`
  (121 packages; **80 unique advisory IDs**, 178 package/advisory matches). The arm64 report has the same
  inventory and findings.
- **Nature of the findings:** all 80 are Debian 13 (trixie) operating-system packages in the base image.
  **No finding is in a Python dependency.** The 25 Python packages in the SBOM have no recorded advisory.
- **Vendor assessment:** the Debian Security Tracker data for the `trixie` release, downloaded 2026-10-16.
  Tracker values change; re-check before relying on them.
- **Application facts used:** the entrypoint is `python autopwn.py`; the application's only runtime external
  process is Nmap, started without a shell ([`modules/nmap_progress.py`](../modules/nmap_progress.py));
  the project loads no SQLite extensions and uses no `ctypes`, `iconv` or `wordexp`.
- **Image facts used:** the SBOM lists no `perl-modules`, `nscd`, systemd daemons, `sshd` or `sudo`.

A signature establishes where the image came from, not that it is safe.

## Result

| Debian trixie status / urgency | Count |
| --- | ---: |
| open / unassigned | 48 |
| open / unimportant | 30 |
| undetermined / unassigned | 1 |
| resolved / unimportant | 1 |

Debian has **not fixed most of these in trixie**: 78 are `open`,
1 is `resolved` and 1 is `undetermined`.
Rebuilding from a newer snapshot of the same release will therefore clear very few of them; the upstream
fixes are in Debian unstable or newer releases.

| Tier | Meaning | IDs |
| --- | --- | ---: |
| **A** | The vulnerable program, library function or platform code is **not installed, not executed by the application, or not built for the supported platforms.** These are candidates for `not_affected` OpenVEX statements. | 42 |
| **B** | The code is **linked into Nmap, Python or both**, and use of the vulnerable interface with target-influenced data has not been ruled out. These remain **open**. | 38 |

Tier A is an analysis for a reviewer, not a conclusion. Per the policy, every statement needs an independent human
to confirm the call path, and "no fix is available" is never a justification on its own.

## What this means for the next release

The release gate blocks on any applicable image finding unless it is fixed or covered by a reviewed OpenVEX
statement, and v2.6.0 was signed through the authenticity-backfill path, which publishes findings **without**
clearing them. A new release will fail the gate as things stand. Realistic options, in order of effort:

1. **Review and publish OpenVEX statements for tier A** (independent reviewer; reassess at least every 90 days).
   This addresses 42 of 80 IDs but not tier B.
2. **Reduce what tier B can reach**: run Nmap without full root (file capabilities `cap_net_raw`, `cap_net_admin`)
   and add an unprivileged `USER` for the application, then re-scan. Refresh the pinned base image and Debian
   snapshot (`python scripts/update_base_image.py`) to pick up whichever of the 80 Debian fixes by then.
3. **Change the base image** to one with fewer, better-maintained packages (for example Alpine or a distroless
   variant that provides Nmap) and re-scan. This is a larger change and needs its own review.
4. **Amend the policy** only through its normal review process, if the maintainer decides that unpatched
   vendor-`unimportant` operating-system advisories should not block releases.

## Per-package reasoning

| Source package | Installed binary packages | Tier | Reasoning |
| --- | --- | --- | --- |
| acl | `libacl1` | A | Library loaded only by file utilities such as `ls`, `tar` and `coreutils`; not by the application or Nmap. |
| apt | `apt`, `libapt-pkg7.0` | A | Package manager used only while the image is built; never executed at runtime. |
| attr | `libattr1` | A | Library loaded only by file utilities; not by the application or Nmap. |
| coreutils | `coreutils` | A | Basic utilities (`chown`, `sort`) never invoked by the application. |
| dash | `dash` | A | Provides `/bin/sh` for build steps. The application starts Nmap with `shell=False` and an argument vector, so no shell parses scan input. |
| diffutils | `diffutils` | A | Utility never invoked by the application. |
| ncurses | `libncursesw6`, `libtinfo6`, `ncurses-base`, `ncurses-bin` | A | The advisories affect the `infocmp` and terminfo-compiler tools. Neither is executed by the application, and the application does not use Python's `curses` module. |
| pam | `libpam0g`, `libpam-modules`, `libpam-modules-bin`, `libpam-runtime` | A | The advisories affect the `pam_namespace` and `pam_userdb` modules. No PAM-using service (login daemon, SSH, `sudo`) is installed or run; the application never authenticates through PAM. |
| perl | `perl-base` only (no `perl-modules`) | A | `Pod::Text` and `Archive::Tar` ship in `perl-modules`, which the image SBOM does not contain; `perl-base` exists for Debian packaging scripts and is never run by the application. The regular-expression issue needs attacker-supplied patterns to a Perl process, and none runs. |
| shadow | `login.defs`, `passwd` | A | Account-management tooling that the application never executes. |
| systemd | `libsystemd0`, `libudev1` | A | Only the client libraries are installed. The advisories concern `journald` sealed logs, `systemd-oomd`, `systemd-homed` and file-permission handling in the service manager; none of those programs are installed, and no init system runs in the container. |
| tar | `tar` | A | Archive tool never invoked by the application (the application reads gzip data through Python's `gzip` module). Exploitation needs someone to run `tar` inside the container. |
| util-linux | `bsdutils`, `login`, `mount`, `util-linux`, `libblkid1`, `libmount1`, `libuuid1`, `libsmartcols1`, `liblastlog2-2` | A | The advisories affect `chfn`/`chsh`, `login`, `mount` helpers, `nsenter` and bind-mount handling. The container entrypoint is `python autopwn.py`, the application invokes no such program (its only external process is Nmap, started without a shell), and exploiting any of them needs the ability to run commands inside the container, which already implies full control of a root-run process. |
| bzip2 | `libbz2-1.0` | B | Linked by Python's optional `bz2` module, which the application does not import. Kept open pending review because it ships in the interpreter's dependency set. |
| gcc-14 | `libgcc-s1`, `libstdc++6`, `gcc-14-base` | B | `libstdc++` is linked into Nmap. The advisories concern an `erase_if` priority-queue helper and aligned `operator new` overflow; whether Nmap reaches them with target-controlled sizes is unverified, so they stay open. |
| glibc | `libc6`, `libc-bin` | B | Linked into every process, including Python and Nmap. Most advisories concern specific interfaces (`strfmon`, `tdelete`, `wordexp`, resolver `ns_print*`, `fopen ,ccs=`, SHIFT_JISX0213/EUC_JISX0213 conversion) or need control over the dynamic loader or `resolv.conf`. Whether Python or Nmap call the vulnerable interfaces with target-influenced data has not been verified per function, so they stay open unless adjusted individually below. |
| libpcap | `libpcap0.8t64` | B | Linked into Nmap for packet capture and BPF filtering. Most advisories need attacker-controlled BPF programs, which Nmap builds itself rather than taking from a target. Whether the BPF-interpreter issues are reachable from target data has not been established, so they stay open. The two `rpcap` advisories concern code Nmap does not use and are adjusted individually below. |
| nmap | `nmap`, `nmap-common` | B | Nmap is the application's scanning engine and parses network data that the scanned target controls (service banners, IPv6 packets). A crafted response can crash or hang a scan. The application treats a failed Nmap run as a failed scan and never reuses stale results (see `tests/unit/test_nmap_backend.py`), but memory-safety flaws in a root-run packet parser remain a real exposure. |
| sqlite3 | `libsqlite3-0` | B | Used by Python's `sqlite3` module for the local vulnerability database, which the project builds itself and queries with parameterized statements. The project loads no SQLite extensions. The advisories concern the session and zipfile extensions and crafted SQL. Local-only exposure; stays open pending review. |
| zlib | `zlib1g` | B | Used by Python's `zlib`/`gzip` modules to read NVD feeds and HTTP responses. The advisories concern `crc32_combine` and the `gz*` file API; Python's gzip module uses neither, but this has not been independently reviewed, so they stay open. |

## Every advisory

The tier shown is final, after the per-ID adjustments noted in the last column. "unassigned" means Debian has not yet
assigned an urgency.

| ID | Source package | Debian trixie | Tier | Summary |
| --- | --- | --- | --- | --- |
| `CVE-2026-54369` | acl | open / unassigned | A | acl before version 2.4.0 contains a symlink traversal vulnerability in the libacl pathname-based functions acl |
| `CVE-2026-54370` | acl | open / unassigned | A | acl before version 2.4.0 contains a time-of-check to time-of-use (TOCTOU) race condition vulnerability that al |
| `CVE-2011-3374` | apt | open / unimportant | A | It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, le |
| `CVE-2026-54371` | attr | open / unassigned | A | attr before version 2.6.0 contains a symlink traversal vulnerability in the getfattr and setfattr utilities th |
| `CVE-2017-18018` | coreutils | open / unimportant | A | In GNU Coreutils through 8.29, chown-core.c in chown and chgrp does not prevent replacement of a plain file wi |
| `CVE-2025-5278` | coreutils | open / unimportant | A | A flaw was found in GNU Coreutils. The sort utility's begfield() function is vulnerable to a heap buffer under |
| `CVE-2026-56391` | coreutils | open / unimportant | A | GNU coreutils uniq is vulnerable to an out‑of‑bounds read due to incorrect handling of multibyte input when th |
| `CVE-2026-56392` | coreutils | open / unimportant | A | GNU coreutils unexpand is vulnerable to a heap-based buffer overflow due to an integer overflow during buffer  |
| `CVE-2026-102473` | dash | open / unimportant | A | A flaw was found in dash. When built without libc fnmatch, the internal pmatch() matcher implements * by unbou |
| `CVE-2026-102474` | dash | open / unimportant | A | A flaw was found in dash. The printf builtin reserves four bytes before converting a Unicode \u or \U escape,  |
| `CVE-2026-53910` | diffutils | open / unimportant | A | diff3 tool from GNU diffutils is vulnerable to a heap‑based buffer overflow due to multiple signed integer ove |
| `CVE-2026-89092` | glibc | open / unassigned | A | The nscd service in the GNU C Library 2.3.4 onwards may crash due to a  stack overflow when a malicious DNS se - Concerns `nscd`, which the image does not contain. |
| `CVE-2026-97399` | glibc | open / unassigned | A | The strncasecmp function in the GNU C Library 2.24 and later optimized for the Power8 architecture may read on - Concerns a Power8-only optimized routine; the images are built for amd64 and arm64. |
| `CVE-2026-18238` | libpcap | open / unimportant | A | The rpcap client code that processes a RPCAP_MSG_PACKET message received from the server incorrectly validates - rpcap client code; Nmap captures from local interfaces and does not open `rpcap://` sources. |
| `CVE-2026-18313` | libpcap | open / unimportant | A | rpcapd can allocate up to 65536 bytes per each RPCAP_MSG_UPDATEFILTER_REQ or RPCAP_MSG_STARTCAP_REQ message re - Concerns `rpcapd`, which the image does not contain. |
| `CVE-2025-6141` | ncurses | open / unassigned | A | A vulnerability has been found in GNU ncurses up to 6.5-20250322 and classified as problematic. This vulnerabi |
| `CVE-2025-69720` | ncurses | open / unassigned | A | The infocmp command-line tool in ncurses before 6.5-20251213 has a stack-based buffer overflow in analyze_stri |
| `CVE-2025-8941` | pam | undetermined / unassigned | A | A flaw was found in linux-pam. The pam_namespace module may improperly handle user-controlled paths, allowing  |
| `CVE-2026-54411` | pam | open / unassigned | A | Linux-PAM through 1.7.2 contains an observable timing discrepancy (CWE-208) in the pam_userdb module's plainte |
| `CVE-2011-4116` | perl | open / unimportant | A | _is_safe in the File::Temp module for Perl does not properly handle symlinks. |
| `CVE-2026-15534` | perl | open / unassigned | A | Perl versions through 5.45.1 have out-of-bounds heap reads and writes during regular expression matching via a |
| `CVE-2026-82560` | perl | open / unassigned | A | Pod::Text versions before 6.1.1 for Perl allow CPU and memory exhaustion formatting a POD document whose =over |
| `CVE-2026-9538` | perl | open / unassigned | A | Archive::Tar versions before 3.10 for Perl allow memory exhaustion via attacker controlled entry size field in |
| `CVE-2007-5686` | shadow | open / unimportant | A | initscripts in rPath Linux 1 sets insecure permissions for the /var/log/btmp file, which allows local users to |
| `CVE-2024-56433` | shadow | open / unassigned | A | shadow-utils (aka shadow) 4.4 through 4.17.0 establishes a default /etc/subuid behavior (e.g., uid 100000 thro |
| `CVE-2013-4392` | systemd | open / unimportant | A | systemd, when updating file permissions, allows local users to change the permissions and SELinux security con |
| `CVE-2023-31437` | systemd | open / unimportant | A | An issue was discovered in systemd 253. An attacker can modify a sealed log file such that, in some views, not |
| `CVE-2023-31438` | systemd | open / unimportant | A | An issue was discovered in systemd 253. An attacker can truncate a sealed log file and then resume log sealing |
| `CVE-2023-31439` | systemd | open / unimportant | A | An issue was discovered in systemd 253. An attacker can modify the contents of past events in a sealed log fil |
| `CVE-2026-15059` | systemd | open / unassigned | A | Local unprivileged users can terminate arbitrary local processes via a systemd-oomd IPC API due to a missing p |
| `CVE-2026-16742` | systemd | open / unassigned | A | systemd-homed contains a local privilege escalation bug via arbitrary system group addition to a local, logged |
| `CVE-2026-40228` | systemd | open / unassigned | A | In systemd 259, systemd-journald can send ANSI escape sequences to the terminals of arbitrary users when a "lo |
| `CVE-2005-2541` | tar | open / unimportant | A | Tar 1.15.1 does not properly warn the user when extracting setuid or setgid files, which may allow local users |
| `CVE-2026-18477` | tar | open / unassigned | A | A TOCTOU (Time-of-Check Time-of-Use) vulnerability in GNU tar's incremental dumpdir 'X' rename handling allows |
| `CVE-2026-18508` | tar | open / unassigned | A | A flaw was found in GNU tar. When extracting an archive with the --one-top-level option, hardlink targets are  |
| `CVE-2026-5704` | tar | open / unassigned | A | A flaw was found in tar. A remote attacker could exploit this vulnerability by crafting a malicious archive, l |
| `CVE-2022-0563` | util-linux | open / unimportant | A | A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline l |
| `CVE-2026-3184` | util-linux | open / unassigned | A | A flaw was found in util-linux. Improper hostname canonicalization in the `login(1)` utility, when invoked wit |
| `CVE-2026-76642` | util-linux | open / unassigned | A | util-linux versions through 2.41.5 and 2.42.2 fail to check mount helper exit status before running post-mount |
| `CVE-2026-78408` | util-linux | open / unassigned | A | The nsenter --join-cgroup option opens the target cgroup.procs file as root and leaves that file descriptor op |
| `CVE-2026-78409` | util-linux | open / unassigned | A | The X-mount.subdir option uses a detached-tree fast path on Linux 6.15 and later and passes the configured sub |
| `CVE-2026-78410` | util-linux | open / unassigned | A | A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but do not pin that sou |
| `CVE-2026-42250` | bzip2 | open / unassigned | B | bzip2 contains an off‑by‑one error in the bzip2recover utility. When processing a specially crafted file, the  |
| `CVE-2026-102010` | gcc-14 | open / unassigned | B | A flaw was found in GCC. When an application calls the erase_if function on a binary heap priority queue in li |
| `CVE-2026-95619` | gcc-14 | open / unassigned | B | A flaw was found in libstdc++. An integer overflow can occur when processing large inputs to the aligned opera |
| `CVE-2010-4756` | glibc | open / unimportant | B | The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a |
| `CVE-2018-20796` | glibc | open / unimportant | B | In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Unc |
| `CVE-2019-1010022` | glibc | open / unimportant | B | GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass stack guard protection. |
| `CVE-2019-1010023` | glibc | open / unimportant | B | GNU Libc current is affected by: Re-mapping current loaded library with malicious ELF file. The impact is: In  |
| `CVE-2019-1010024` | glibc | open / unimportant | B | GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass ASLR using cache of thr |
| `CVE-2019-1010025` | glibc | open / unimportant | B | GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may guess the heap addresses of pt |
| `CVE-2019-9192` | glibc | open / unimportant | B | In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Unc |
| `CVE-2026-18374` | glibc | open / unassigned | B | Passing an effectively empty string to the `,ccs=` syntax extension of the mode argument in the `fopen` functi |
| `CVE-2026-19499` | glibc | open / unassigned | B | Calling strfmon and strfmon_l in the GNU C Library version 2.38 to 2.44 can write past the end of the caller-s |
| `CVE-2026-19542` | glibc | open / unassigned | B | Calling tdelete on a sufficiently deep tree in the GNU C Library version 2.1 to 2.44 may write one pointer pas |
| `CVE-2026-5435` | glibc | open / unassigned | B | The deprecated functions ns_printrrf, ns_printrr and fp_nquery in the GNU C Library version 2.2 and newer fail |
| `CVE-2026-6238` | glibc | open / unassigned | B | The deprecated functions ns_printrrf, ns_printrr and fp_nquery in the GNU C Library version 2.0.1 to version 2 |
| `CVE-2026-6368` | glibc | open / unassigned | B | Calling wordexp with WRDE_APPEND in the GNU C Library version 2.0 to version 2.43 can cause the interface to r |
| `CVE-2026-6791` | glibc | open / unassigned | B | When expanding paths that begin with a tilde (~) followed by a username, the internal parse_tilde function ext |
| `CVE-2026-77117` | glibc | open / unassigned | B | Converting crafted SHIFT_JISX0213 input to UCS-4 or the internal wide character encoding, for example with ico |
| `CVE-2026-80489` | glibc | open / unassigned | B | Converting crafted EUC_JISX0213 input to UCS-4 or the internal wide character encoding, for example with iconv |
| `CVE-2026-8674` | glibc | open / unassigned | B | Initializing the DNS stub resolver from an /etc/resolv.conf file, or a LOCALDOMAIN environment variable, whose |
| `CVE-2026-86805` | glibc | open / unassigned | B | A time-of-check to time-of-use (TOCTOU) race condition in the dynamic loader (ld.so) of the GNU C Library (gli |
| `CVE-2026-95818` | glibc | open / unassigned | B | A stack-based buffer overflow in the dynamic loader (ld.so) of the GNU C Library (glibc) versions 2.14 through |
| `CVE-2025-11961` | libpcap | open / unassigned | B | pcap_ether_aton() is an auxiliary function in libpcap, it takes a string argument and returns a fixed-size all |
| `CVE-2026-0799` | libpcap | open / unassigned | B | In BPF instructions that load/store a value from/to a scratch memory register the register index is an unsigne |
| `CVE-2026-31911` | libpcap | open / unassigned | B | libpcap BPF interpreter calls abort() if it encounters a BPF instruction that has an invalid opcode.  In parti |
| `CVE-2026-31912` | libpcap | open / unassigned | B | libpcap BPF interpreter detects neither reaching the end of the filter program buffer due to lack of a return  |
| `CVE-2026-6244` | libpcap | open / unassigned | B | libpcap BPF interpreter for the 'div #k' and 'mod #k' ALU instructions does not check whether the immediate va |
| `CVE-2026-6554` | libpcap | open / unassigned | B | libpcap BPF interpreter treats the offset in the 'ja L' BPF instruction as a signed integer to implement loopi |
| `CVE-2018-15173` | nmap | open / unimportant | B | Nmap through 7.70, when the -sV option is used, allows remote attackers to cause a denial of service (stack co |
| `CVE-2026-58058` | nmap | open / unimportant | B | Nmap through 7.99 does not keep the IPv6 extension-header walk within the captured packet in ipv6_get_data_pri |
| `CVE-2026-72712` | nmap | open / unimportant | B | Nmap versions up to and including 7.99 contains a denial of service vulnerability that allows remote attackers |
| `CVE-2021-45346` | sqlite3 | open / unimportant | B | A Memory Leak vulnerability exists in SQLite Project SQLite3 3.35.1 and 3.37.0 via maliciously crafted SQL Que |
| `CVE-2025-70873` | sqlite3 | open / unimportant | B | An information disclosure issue in the zipfileInflate function in the zipfile extension in SQLite v3.51.1 and  |
| `CVE-2026-39113` | sqlite3 | resolved / unimportant | B | Buffer Overflow vulnerability in SQLite affected version source snapshots/builds containing Fossil check-in 8b |
| `CVE-2026-50812` | sqlite3 | open / unassigned | B | A NULL pointer dereference in the SQLite Session Extension in SQLite 3.53.1 and SQLite trunk builds before che |
| `CVE-2026-50813` | sqlite3 | open / unassigned | B | An issue in SQLite before Fossil check-in 869a51ae84df allows a local attacker to obtain sensitive information |
| `CVE-2026-27171` | zlib | open / unassigned | B | zlib before 1.3.2 allows CPU consumption via crc32_combine64 and crc32_combine_gen64 because x2nmodp can do ri |
| `CVE-2026-85091` | zlib | open / unassigned | B | zlib versions 1.3.1.2 through 1.3.2 contain a heap buffer overflow vulnerability in the gz_vacate() function w |

## Limits of this triage

- It reads the project's code and the image inventory; it did not run the vulnerable code paths or fuzz Nmap.
- Tier B entries are **unresolved**, not accepted. Verify per-interface use before any is marked unaffected.
- Debian's `unimportant` urgency is the vendor's judgment about typical use, not about a root-run network scanner.
- Re-run this triage whenever the base image, Debian snapshot, Nmap version or application code that starts
  processes changes.
