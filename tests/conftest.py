import os
import sys
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, MagicMock
import pytest

# Add the project root to the Python path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    # Cleanup after test
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def temp_file(temp_dir):
    """Create a temporary file within the temp directory."""
    def _create_temp_file(filename="test_file.txt", content=""):
        file_path = temp_dir / filename
        file_path.write_text(content)
        return file_path
    return _create_temp_file


@pytest.fixture
def mock_config():
    """Provide a mock configuration object."""
    config = MagicMock()
    config.target = "192.168.1.1"
    config.port = 80
    config.timeout = 5
    config.threads = 10
    config.verbose = False
    config.output = "autopwn_test.log"
    return config


@pytest.fixture
def mock_scanner():
    """Provide a mock scanner object."""
    scanner = Mock()
    scanner.scan = Mock(return_value={
        "scan": {
            "192.168.1.1": {
                "tcp": {
                    80: {"state": "open", "name": "http"},
                    443: {"state": "open", "name": "https"},
                    22: {"state": "closed", "name": "ssh"}
                }
            }
        }
    })
    return scanner


@pytest.fixture
def mock_requests(monkeypatch):
    """Mock the requests library."""
    mock = Mock()
    mock.get = Mock()
    mock.post = Mock()
    mock.Session = Mock()
    monkeypatch.setattr("requests", mock)
    return mock


@pytest.fixture
def sample_vulnerability_data():
    """Provide sample vulnerability data for testing."""
    return {
        "CVE-2021-44228": {
            "description": "Apache Log4j2 vulnerability",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "affected_versions": ["2.0-beta9 to 2.14.1"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
        },
        "CVE-2014-0160": {
            "description": "OpenSSL Heartbleed vulnerability",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "affected_versions": ["1.0.1 to 1.0.1f"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"]
        }
    }


@pytest.fixture
def sample_exploit_data():
    """Provide sample exploit data for testing."""
    return [
        {
            "id": "12345",
            "name": "Apache Log4j2 RCE",
            "cve": ["CVE-2021-44228"],
            "platform": "java",
            "verified": True,
            "published": "2021-12-10"
        },
        {
            "id": "67890",
            "name": "OpenSSL Heartbleed Memory Disclosure",
            "cve": ["CVE-2014-0160"],
            "platform": "linux",
            "verified": True,
            "published": "2014-04-07"
        }
    ]


@pytest.fixture
def mock_nmap_result():
    """Provide a mock nmap scan result."""
    return {
        "nmap": {
            "command_line": "nmap -sV -sC 192.168.1.1",
            "scaninfo": {"tcp": {"method": "syn", "services": "1-65535"}},
            "scanstats": {
                "timestr": "Mon Jan 01 00:00:00 2024",
                "elapsed": "10.50",
                "uphosts": "1",
                "downhosts": "0",
                "totalhosts": "1"
            }
        },
        "scan": {
            "192.168.1.1": {
                "hostnames": [{"name": "test-host.local", "type": "PTR"}],
                "addresses": {"ipv4": "192.168.1.1"},
                "vendor": {},
                "status": {"state": "up", "reason": "syn-ack"},
                "tcp": {
                    80: {
                        "state": "open",
                        "reason": "syn-ack",
                        "name": "http",
                        "product": "Apache httpd",
                        "version": "2.4.41",
                        "extrainfo": "(Ubuntu)",
                        "conf": "10",
                        "cpe": "cpe:/a:apache:http_server:2.4.41"
                    }
                }
            }
        }
    }


@pytest.fixture
def mock_http_response():
    """Create a mock HTTP response."""
    def _create_response(status_code=200, text="", headers=None):
        response = Mock()
        response.status_code = status_code
        response.text = text
        response.content = text.encode() if isinstance(text, str) else text
        response.headers = headers or {"Content-Type": "text/html"}
        response.raise_for_status = Mock()
        if status_code >= 400:
            response.raise_for_status.side_effect = Exception(f"HTTP {status_code}")
        return response
    return _create_response


@pytest.fixture
def captured_output(monkeypatch):
    """Capture stdout and stderr for testing console output."""
    import io
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    
    monkeypatch.setattr("sys.stdout", stdout_capture)
    monkeypatch.setattr("sys.stderr", stderr_capture)
    
    yield {
        "stdout": stdout_capture,
        "stderr": stderr_capture
    }


@pytest.fixture(autouse=True)
def reset_sys_modules():
    """Reset sys.modules to prevent module caching issues between tests."""
    modules_before = set(sys.modules.keys())
    yield
    modules_after = set(sys.modules.keys())
    for module in modules_after - modules_before:
        if module.startswith(("modules.", "api", "autopwn")):
            sys.modules.pop(module, None)


@pytest.fixture
def mock_logger(monkeypatch):
    """Mock the logger module."""
    logger = Mock()
    logger.info = Mock()
    logger.warning = Mock()
    logger.error = Mock()
    logger.debug = Mock()
    logger.critical = Mock()
    return logger


@pytest.fixture
def sample_html_content():
    """Provide sample HTML content for web testing."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Page</title>
    </head>
    <body>
        <h1>Welcome to Test Page</h1>
        <form action="/login" method="post">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="submit" value="Login" />
        </form>
        <a href="/admin">Admin Panel</a>
        <a href="/user/profile">User Profile</a>
        <script>var apiKey = "test123";</script>
    </body>
    </html>
    """


@pytest.fixture
def mock_rich_console(monkeypatch):
    """Mock Rich console for testing output."""
    from unittest.mock import Mock
    console = Mock()
    console.print = Mock()
    console.log = Mock()
    console.rule = Mock()
    console.status = Mock()
    return console


# Markers for test categorization
def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "slow: Slow running tests")