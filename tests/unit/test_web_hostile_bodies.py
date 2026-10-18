# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""A target controls the response body, so no check may take longer than a moment to read one.

Python's `re` holds the GIL while it matches, so a body that makes a pattern backtrack stalls the scan,
its Stop button and every other dashboard thread until the match ends (minutes for the bodies below
with the unbounded patterns they replaced).
"""
import time
from unittest.mock import MagicMock

import pytest

from autopwn_suite.web import poc_runtime
from autopwn_suite.web.content import inspect_content
from autopwn_suite.web.sqli import SQLIScanner

LIMIT_SECONDS = 2.0

SQL_BODIES = [
    "microsoft odbc " * 12_000, "microsoft jet " * 12_000, "microsoft access " * 12_000, "warning " * 20_000,
    "postgresql " * 15_000, "pg_query() " * 15_000, "sqlite " * 20_000, "syntax error " * 12_000, "a" * 1_000_000,
]
FILE_BODIES = {
    "/.env": ["\n" * 100_000, " \n" * 50_000, "A" * 100_000, "export " * 14_000],
    "/dump.sql": ["-- MySQL" * 12_000, "-- PostgreSQL" * 8_000],
}
ERROR_BODIES = ["a" * 100_000, "Exception:" * 10_000, "AException:" + "a" * 100_000, "Uncaught " + "a" * 100_000, "Traceback (most recent call last):\n" * 3_000]


def seconds(call, *args):
    started = time.perf_counter()
    call(*args)
    return time.perf_counter() - started


@pytest.mark.unit
@pytest.mark.parametrize("body", SQL_BODIES, ids=lambda body: body[:14])
def test_sql_error_patterns_stay_fast_on_hostile_bodies(body):
    assert seconds(SQLIScanner(MagicMock(), MagicMock())._errors, body) < LIMIT_SECONDS
    assert seconds(poc_runtime._sql_errors, body) < LIMIT_SECONDS


@pytest.mark.unit
@pytest.mark.parametrize("path,body", [(path, body) for path, bodies in FILE_BODIES.items() for body in bodies], ids=lambda value: str(value)[:14])
def test_exposed_file_checks_stay_fast_on_hostile_bodies(web_response, path, body):
    response = web_response(body, url="http://example.com" + path, headers={"Content-Type": "text/plain"})
    assert seconds(inspect_content, "http://example.com" + path, response, MagicMock()) < LIMIT_SECONDS


@pytest.mark.unit
@pytest.mark.parametrize("body", ERROR_BODIES, ids=lambda body: body[:14])
def test_error_page_signatures_stay_fast_on_hostile_bodies(web_response, body):
    response = web_response(body, status=500, headers={"Content-Type": "text/plain"})
    assert seconds(inspect_content, "http://example.com/", response, MagicMock()) < LIMIT_SECONDS


@pytest.mark.unit
def test_environment_file_keys_are_still_found_on_ordinary_lines(web_response):
    body = "# comment\r\nexport APP_NAME=demo\r\n  DB_PASSWORD = secret\r\nTOKEN=abc\r\n"
    results = inspect_content("http://example.com/.env", web_response(body, headers={"Content-Type": "text/plain"}), MagicMock())
    assert [item["type"] for item in results] == ["EXPOSED_FILE"]
