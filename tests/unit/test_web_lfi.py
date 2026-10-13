from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest
from requests.exceptions import ConnectionError

from modules.web.lfi import LFIScanner


@pytest.mark.unit
@pytest.mark.parametrize("content,payload", [
    ("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", "/second"),
    ("root:*:0:0:System Administrator:/var/root:/bin/sh", "/second"),
    ("[fonts]\n[extensions]\n[mci extensions]\n[files]\n", "C:/Windows/win.ini"),
])
def test_repeatable_new_file_content_is_candidate(web_response, content, payload):
    scanner = LFIScanner(MagicMock(), MagicMock())
    scanner.lfi_tests = ["/first", payload]

    def respond(url, **kwargs):
        params = parse_qs(urlsplit(url).query)
        assert params["language"] == ["en"] or params["file"] == ["original"]
        return web_response(content if params["file"] == [payload] else "normal", url=url)

    with patch("modules.web.lfi.get", side_effect=respond) as get:
        found = scanner.test_lfi("http://example.com/page?file=original&language=en")
        assert len(found) == 1
        assert found[0]["type"] == "LFI"
        assert found[0]["parameter"] == "file"
        assert "Repeatable file content" in found[0]["evidence"]
        assert payload in parse_qs(urlsplit(get.call_args_list[2].args[0]).query)["file"]


@pytest.mark.unit
@pytest.mark.parametrize("text", ["root:x:0:0:root:/root:/bin/bash", "[fonts]\n[extensions]\n", "Path: /etc/passwd", "[fonts]\n"])
def test_existing_file_content_and_reflected_paths_are_not_lfi(web_response, text):
    scanner = LFIScanner(MagicMock(), MagicMock())
    with patch("modules.web.lfi.get", return_value=web_response(text)):
        assert scanner.test_lfi("http://example.com/page?file=readme") == []
    scanner.console.print.assert_not_called()


@pytest.mark.unit
def test_timeout_and_url_without_query():
    scanner = LFIScanner(MagicMock(), MagicMock())
    with patch("modules.web.lfi.get", side_effect=ConnectionError) as get:
        assert scanner.test_lfi("http://example.com/page") == []
        get.assert_not_called()
        assert scanner.test_lfi("http://example.com/page?file=readme") == []
    scanner.log.logger.assert_called_once()


def test_confirmed_file_input_is_not_retested_for_every_router_value(web_response):
    scanner = LFIScanner(MagicMock(), MagicMock())

    def respond(url, **kwargs):
        page = parse_qs(urlsplit(url).query).get("page", [""])[0]
        return web_response("root:x:0:0:root:/root:/bin/bash" if "etc/passwd" in page else "Normal page", url=url)

    with patch("modules.web.lfi.get", side_effect=respond) as get:
        assert len(scanner.test_lfi("http://example.com/index.php?page=home.php")) == 1
        initial_requests = get.call_count
        assert scanner.test_lfi("http://example.com/index.php?page=other.php") == []
        assert get.call_count == initial_requests
        # A different accompanying input is a different request context.
        assert len(scanner.test_lfi("http://example.com/index.php?page=other.php&language=en")) == 1
