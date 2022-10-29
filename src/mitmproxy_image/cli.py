# Why does this file exist, and why not put this in `__main__`?
#
# You might be tempted to import things from `__main__` later,
# but that will cause problems: the code will get executed twice:
#
# - When you run `python -m mitmproxy_image` python will execute
#   `__main__.py` as a script. That means there won't be any
#   `mitmproxy_image.__main__` in `sys.modules`.
# - When you import `__main__` it will get executed again (as a module) because
#   there's no `mitmproxy_image.__main__` in `sys.modules`.

"""Module that contains the command line application."""
import click

from . import script

__version__ = "2.0.0rc0"


@click.group()
@click.version_option(version=__version__)
def main():
    """
    Run the main program.

    This function is executed when you type `mitmproxy-image` or `python -m mitmproxy_image`.

    This is only wrapper for `mitmproxy` function.

    Arguments:
        args: Arguments passed from the command line.

    Returns:
        An exit code.
    """


@main.command()
def print_path():
    print(script.__file__)
