"""Tests for the `cli` module."""

import pytest
from click.testing import CliRunner

from mitmproxy_image import cli


def test_main():
    """Basic CLI test."""
    with pytest.raises(SystemExit):
        assert cli.main([])


def test_show_help():
    """Show help."""
    runner = CliRunner()
    result = runner.invoke(cli.main, ["--help"])
    assert result.exit_code == 0
    assert result.output
