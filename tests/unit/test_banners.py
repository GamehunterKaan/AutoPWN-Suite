"""
Unit tests for the banners module.
"""
from unittest.mock import MagicMock, call

import pytest
from rich.panel import Panel

from modules.banners import print_banner


@pytest.mark.unit
def test_print_banner():
    """Verify that print_banner calls console.print."""
    mock_console = MagicMock()
    print_banner(mock_console)

    # Check that print was called at least once with a Panel object
    assert mock_console.print.call_count > 0
    assert isinstance(mock_console.print.call_args[0][0], Panel)