"""One validated control schema for CLI, dashboard, profiles and schedules."""

from copy import deepcopy


CHECKS = {
    "headers": "Headers & cookies", "directories": "Directories & indexes",
    "exposed_files": "Exposed files", "errors": "Debug & error disclosure",
    "cors": "CORS policy", "redirects": "Open redirects", "sqli": "SQL injection",
    "boolean_sqli": "Blind SQL injection", "xss": "Reflected XSS", "lfi": "File inclusion",
    "tls": "TLS & certificates", "methods": "HTTP methods", "host_headers": "Host headers",
}
TYPE_CHECK = {"WEB_CONFIG": "headers", "DIR": "directories", "DIR_LISTING": "directories",
              "EXPOSED_FILE": "exposed_files", "DEBUG_DISCLOSURE": "errors", "ERROR_DISCLOSURE": "errors",
              "CORS": "cors", "CORS_CONFIG": "cors", "OPEN_REDIRECT": "redirects", "SQLI": "sqli",
              "SQLI_BOOLEAN": "boolean_sqli", "XSS": "xss", "LFI": "lfi", "TLS_TRUST": "tls",
              "TLS_CERTIFICATE": "tls", "TLS_PROTOCOL": "tls", "HTTP_METHODS": "methods",
              "TRACE_ENABLED": "methods", "HOST_HEADER": "host_headers"}
LIMITS = {"speed": (3, 0, 5), "request_delay_ms": (0, 0, 60000),
          "request_budget": (10000, 20, 50000), "timeout": (10, 1, 30),
          "max_pages": (250, 1, 2000), "max_urls": (1000, 1, 10000), "max_depth": (5, 0, 10),
          "max_endpoints": (100, 1, 1000), "max_parameters": (5, 1, 20),
          "max_response_kb": (1024, 64, 2048)}


def normalize_options(value=None, existing=None):
    if value is None:
        value = {}
    if not isinstance(value, dict) or (existing is not None and not isinstance(existing, dict)):
        raise ValueError("web_options must be an object")
    options = {name: bounds[0] for name, bounds in LIMITS.items()}
    options["checks"] = {name: True for name in CHECKS}
    for source in (existing or {}, value):
        if set(source) - (set(LIMITS) | {"checks"}):
            raise ValueError("Unknown web scan control")
        for name in LIMITS:
            if name in source:
                options[name] = source[name]
        checks = source.get("checks", {})
        if not isinstance(checks, dict) or set(checks) - set(CHECKS):
            raise ValueError("web check selections contain unknown checks")
        if any(not isinstance(enabled, bool) for enabled in checks.values()):
            raise ValueError("web check selections must be booleans")
        options["checks"].update(checks)
    for name, (_, minimum, maximum) in LIMITS.items():
        number = options[name]
        if isinstance(number, bool) or not isinstance(number, (int, str)):
            raise ValueError(f"web {name} must be an integer")
        try:
            if isinstance(number, str) and not number.strip().lstrip("+-").isdigit():
                raise ValueError()
            number = int(number)
        except ValueError:
            raise ValueError(f"web {name} must be an integer") from None
        if not minimum <= number <= maximum:
            raise ValueError(f"web {name} must be {minimum}-{maximum}")
        options[name] = number
    return deepcopy(options)
