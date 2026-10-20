# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
import sys
from datetime import datetime
from platform import system
from time import sleep

from rich.console import Console

from autopwn_suite import __version__, i18n
from autopwn_suite.banners import print_banner
from autopwn_suite.daemon.daemon_installer import CreateConfig, InstallDaemon, UninstallDaemon
from autopwn_suite.getexploits import GetExploitsFromArray
from autopwn_suite.logger import Logger, console_safe
from autopwn_suite.nist_search import VulnerabilityLookup
from autopwn_suite.report import InitializeReport
from autopwn_suite.scanner import AnalyseScanResults, DiscoverHosts, NoiseScan, PortScan, ResolveScanHosts
from autopwn_suite.searchvuln import SearchSploits
from autopwn_suite.update_checker import (
    UpdateCheckError,
    apply_update,
    check_for_updates,
    format_result,
    format_status,
    resolve_update_channel,
)
from autopwn_suite.utils import (
    CheckConnection as CheckConnection,
)
from autopwn_suite.utils import (
    GetHostsToScan,
    InitArgsAPI,
    InitArgsConf,
    InitArgsMode,
    InitArgsScanType,
    InitArgsTarget,
    InitAutomation,
    InitReport,
    NoHostsFound,
    ParamPrint,
    SaveOutput,
    ScanMode,
    UserConfirmation,
    WebScan,
    check_nmap,
    cli,
)
from autopwn_suite.vulnerability_db import database_status, update_database
from autopwn_suite.web.webvuln import web_endpoints, webvuln
from autopwn_suite.web_ui import FLASK_AVAILABLE, reset_web_account, start_server


def StartScanning(
    args, targetarg, scantype, scanmode, apiKey, console, console2, log, lookup=None
) -> None:

    offline = getattr(args, "offline", False) is True or getattr(args, "vulnerability_source", None) == "offline"
    if offline:
        check_nmap(log, offline=True)
        args.nmap_flags = (args.nmap_flags + " -n").strip()
    else:
        check_nmap(log)

    if scanmode == ScanMode.Noise:
        if offline:
            NoiseScan(targetarg, log, console, scantype, args.noise_timeout, offline=True)
        else:
            NoiseScan(targetarg, log, console, scantype, args.noise_timeout)

    if not args.skip_discovery:
        hosts = (DiscoverHosts(targetarg, console, scantype, scanmode, offline=True) if offline
                 else DiscoverHosts(targetarg, console, scantype, scanmode))
        Targets = GetHostsToScan(hosts, console)
    else:
        Targets = targetarg if isinstance(targetarg, list) else [targetarg]

    ScanPorts, ScanVulns, DownloadExploits = UserConfirmation(args)
    # Web probes can follow server redirects; keep strict offline mode scoped
    # to Nmap and local CVE lookups.
    ScanWeb = False if offline else WebScan()
    if offline:
        DownloadExploits = False

    for host in Targets:
        web_targets = [host]
        web_ports = []
        web_scan_result = None
        if ScanPorts:
            PortScanResults = PortScan(
                host, log, args.speed, args.host_timeout, scanmode, args.nmap_flags
            )
            PortArray = AnalyseScanResults(PortScanResults, log, console, host)
            web_ports = PortArray
            web_scan_result = PortScanResults
            web_targets = ResolveScanHosts(PortScanResults, host)
            if ScanVulns:
                for resolved_host in web_targets:
                    host_ports = [row for row in PortArray if row[0] == resolved_host]
                    if not host_ports:
                        continue
                    VulnsArray = (SearchSploits(host_ports, log, console, console2, apiKey, lookup=lookup)
                                  if lookup is not None else SearchSploits(host_ports, log, console, console2, apiKey))
                    if DownloadExploits and VulnsArray and (lookup is None or lookup.source != "offline"):
                        GetExploitsFromArray(VulnsArray, log, console, console2, resolved_host)

        if ScanWeb:
            for resolved_host in web_targets:
                for endpoint in web_endpoints(resolved_host, web_ports, web_scan_result):
                    if getattr(args, "insecure_tls", False) is True:
                        webvuln(endpoint, log, console, controls={"verify_tls": False})
                    else:
                        webvuln(endpoint, log, console)

    console.print(
        "{time} - Scan completed.".format(
            time=datetime.now().strftime("%b %d %Y %H:%M:%S")
        )
    )


def main() -> None:
    language = i18n.install(i18n.peek_lang_flag(sys.argv[1:]))

    args = cli()
    if args.language is not None and args.language != language:
        i18n.install(args.language)
    if args.no_color:
        console = Console(record=True, color_system=None)
        console2 = Console(record=False, color_system=None)
    else:
        console = Console(record=True, color_system="truecolor")
        console2 = Console(record=False, color_system="truecolor")
    log = Logger(console)

    if args.version:
        print(_("AutoPWN Suite v{version}").format(version=__version__))
        raise SystemExit
    elif args.daemon_install:
        InstallDaemon(console)
        raise SystemExit
    elif args.daemon_uninstall:
        UninstallDaemon(console)
        raise SystemExit
    elif args.create_config:
        CreateConfig(console)
        raise SystemExit

    if args.config:
        InitArgsConf(args, log)

    if getattr(args, "web_reset_account", False) is True:
        try:
            reset_web_account()
        except (OSError, RuntimeError) as exc:
            log.logger("error", _("Dashboard account could not be reset. Check access to AUTOPWN_DATA_DIR."))
            raise SystemExit(1) from exc
        return

    offline = getattr(args, "offline", False) is True or getattr(args, "vulnerability_source", None) == "offline"
    db_path = getattr(args, "vuln_db", None)
    if getattr(args, "update_vuln_db", False) is True:
        if offline:
            raise SystemExit(_("Database downloads require internet. Run --update-vuln-db without --offline."))
        try:
            status = update_database(db_path, lambda msg, current, total: console.print(f"[{current}/{total}] {msg}"))
        except Exception as exc:
            log.logger("error", _("Database update failed; previous database preserved: {error}").format(error=exc))
            raise SystemExit(1) from exc
        console.print(_("Stored {count} CVEs at {path}; updated {updated_at}.").format(
            count=status['count'], path=status['path'], updated_at=status['updated_at']))
        return
    if getattr(args, "vuln_db_status", False) is True:
        console.print(database_status(db_path))
        return
    apply = getattr(args, "apply_update", False) is True
    if apply or getattr(args, "check_update", False) is True:
        if offline:
            raise SystemExit(_("Updates require internet. Run --check-update or --apply-update without --offline."))
        channel = resolve_update_channel(args.update_channel)
        try:
            if apply:
                result = apply_update(channel=channel, branch=args.update_branch, repo=args.update_repo)
                console.print(console_safe(format_result(result)))
            else:
                status = check_for_updates(__version__, channel=channel, branch=args.update_branch,
                                           repo=args.update_repo)
                console.print(console_safe(format_status(status)))
        except UpdateCheckError as exc:
            log.logger("error", console_safe(exc))
            raise SystemExit(1) from exc
        return

    # ── Web UI mode: server only, scans are launched from the browser ───────────
    if getattr(args, "web", False):
        try:
            if not FLASK_AVAILABLE:
                console.print(_("[red]Flask not found. Install it with: pip install flask flask-cors[/red]"))
                raise SystemExit(1)
            web_host = getattr(args, "web_host", "127.0.0.1")
            web_port = getattr(args, "web_port", 8080)
            print_banner(console)
            # start_server blocks until Ctrl+C
            start_server(host=web_host, port=web_port, version=__version__,
                         offline=offline, database=db_path)
        except KeyboardInterrupt:
            raise SystemExit(_("\nWeb UI closed.")) from None
        raise SystemExit
    # ─────────────────────────────────────────────────────────────────────────

    print_banner(console)

    InitAutomation(args)
    if offline and not args.target and not args.host_file:
        raise SystemExit(_("Specify --target or --host-file in offline mode; use IP addresses for airgapped scans."))
    targetarg = InitArgsTarget(args, log)
    scantype = InitArgsScanType(args, log)
    scanmode = InitArgsMode(args, log)
    apiKey = None if offline else InitArgsAPI(args, log)
    ReportMethod, ReportObject = (None, None) if offline else InitReport(args, log)

    ParamPrint(args, targetarg, scantype, scanmode, apiKey, console, log)

    if not hasattr(args, "scan_interval"):
        args.scan_interval = None
    source = "offline" if offline else args.vulnerability_source
    try:
        lookup = VulnerabilityLookup(source, db_path, lazy=True)
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    no_hosts = None
    try:
        if lookup.local:
            console.print(_("Local NVD database: {count} CVEs; updated {updated_at}. Findings are possible vulnerabilities.").format(
                count=lookup.local.metadata['count'], updated_at=console_safe(lookup.local.metadata['updated_at'])))
        StartScanning(args, targetarg, scantype, scanmode, apiKey, console, console2, log, lookup=lookup)
    except NoHostsFound as exc:
        # With a scan interval (the daemon) an empty discovery is a finished round: exiting would make systemd
        # restart the service after 5 seconds, which discovers again and again instead of waiting.
        if not (args.scan_interval and args.scan_interval > 0):
            raise
        no_hosts = exc
    except RuntimeError as exc:
        # A lookup or Nmap failure late in a long scan must not discard the output recorded so far. The
        # reason stays the exit text on stderr (the lookup has logged its own); it is not added to the report.
        log.logger("warning", _("The scan did not finish; saving the output recorded so far."))
        try:
            SaveOutput(console, args.output_type, args.output, args.output_folder, targetarg)
        except OSError:
            log.logger("error", _("The recorded output could not be saved."))
        raise SystemExit(str(exc)) from exc
    finally:
        lookup.close()

    if no_hosts is not None:
        console.print(str(no_hosts))  # nothing was scanned: no report and no output file
    else:
        # Only an offline mode the operator chose suppresses the report; an automatic fallback to the local
        # database (lookup.source) concerns NVD, not SMTP or the webhook.
        if not offline:
            InitializeReport(ReportMethod, ReportObject, log, console)
        SaveOutput(console, args.output_type, args.output, args.output_folder, targetarg)

    if args.scan_interval and args.scan_interval > 0:
        console.print(_("Sleeping for {seconds} seconds...").format(seconds=args.scan_interval))
        sleep(args.scan_interval)


def _write_utf8_when_redirected() -> None:
    """Windows gives redirected or piped output the ANSI code page, which cannot encode the banner and
    the box-drawing text, so the first print would raise UnicodeEncodeError. A console is unaffected."""
    if system().lower() != "windows":
        return
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure") and not stream.isatty():
            stream.reconfigure(encoding="utf-8", errors="replace")


def run() -> None:
    _write_utf8_when_redirected()
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(_("Ctrl+C pressed. Exiting.")) from None


if __name__ == "__main__":
    run()
