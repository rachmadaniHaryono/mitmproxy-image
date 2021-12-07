"""Tests for the `cli` module."""

import pytest

from mitmproxy_image import cli


def test_main():
    """Basic CLI test."""
    with pytest.raises(SystemExit):
        assert cli.main([])


def test_show_help(capsys):
    """
    Show help.

    Arguments:
        capsys: Pytest fixture to capture output.
    """
    with pytest.raises(SystemExit):
        cli.main(["-h"])
    captured = capsys.readouterr()
    assert captured.out
