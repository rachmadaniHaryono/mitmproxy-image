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

import argparse
import asyncio
import os
import signal
import sys
import typing
from typing import List, Optional

from mitmproxy import exceptions, master, options, optmanager
from mitmproxy.tools import cmdline
from mitmproxy.tools.main import process_options
from mitmproxy.utils import arg_check, debug

from .script import MitmImage

try:
    from mitmproxy.tools.main import assert_utf8_env
except Exception:
    assert_utf8_env = None

T = typing.TypeVar("T", bound=master.Master)


def run(
    master_cls: typing.Type[T],
    make_parser: typing.Callable[[options.Options], argparse.ArgumentParser],
    arguments: typing.Sequence[str],
    extra: typing.Callable[[typing.Any], dict] = None,
) -> T:  # pragma: no cover
    """
    run program.

    this is based from
    https://github.com/mitmproxy/mitmproxy/blob/1c10abef000ba2f112bc00119bcdb6707d6ff08e/mitmproxy/tools/main.py#L51

    extra: Extra argument processing callable which returns a dict of
    options.
    """

    async def main() -> T:
        debug.register_info_dumpers()

        opts = options.Options()
        master = master_cls(opts)

        parser = make_parser(opts)

        # To make migration from 2.x to 3.0 bearable.
        if "-R" in sys.argv and sys.argv[sys.argv.index("-R") + 1].startswith("http"):
            print(
                "To use mitmproxy in reverse mode please use --mode reverse:SPEC instead"
            )

        try:
            args = parser.parse_args(arguments)
        except SystemExit:
            arg_check.check()
            sys.exit(1)

        try:
            opts.set(*args.setoptions, defer=True)
            optmanager.load_paths(
                opts,
                os.path.join(opts.confdir, "config.yaml"),
                os.path.join(opts.confdir, "config.yml"),
            )
            # NOTE add mitmproxy_image version
            if args.version:
                print(
                    "\n".join(
                        [
                            debug.dump_system_info(),
                            f"Mitmproxy-image: {__version__}",
                        ]
                    )
                )
                sys.exit(0)
            process_options(parser, opts, args)

            if args.options:
                print(optmanager.dump_defaults(opts, sys.stdout))
                sys.exit(0)
            if args.commands:
                master.commands.dump()
                sys.exit(0)
            if extra:
                if args.filter_args:
                    master.log.info(
                        f"Only processing flows that match \"{' & '.join(args.filter_args)}\""
                    )
                opts.update(**extra(args))

        except exceptions.OptionsError as e:
            print("{}: {}".format(sys.argv[0], e), file=sys.stderr)
            sys.exit(1)

        loop = asyncio.get_event_loop()

        def _sigint(*_):
            loop.call_soon_threadsafe(
                getattr(master, "prompt_for_exit", master.shutdown)
            )

        def _sigterm(*_):
            loop.call_soon_threadsafe(master.shutdown)

        # We can't use loop.add_signal_handler because that's not available on Windows' Proactorloop,
        # but signal.signal just works fine for our purposes.
        signal.signal(signal.SIGINT, _sigint)
        signal.signal(signal.SIGTERM, _sigterm)

        # initiate MitmImage
        ao_obj = MitmImage()
        master.addons.add(ao_obj)
        loop.create_task(ao_obj.upload_worker())
        loop.create_task(ao_obj.post_upload_worker())
        loop.create_task(ao_obj.flow_remove_worker())
        loop.create_task(ao_obj.client_worker())

        await master.run()
        return master

    return asyncio.run(main())


def mitmproxy(args=None) -> typing.Optional[int]:  # pragma: no cover
    """run mitmproxy (custom).

    this is based from
    https://github.com/mitmproxy/mitmproxy/blob/1c10abef000ba2f112bc00119bcdb6707d6ff08e/mitmproxy/tools/main.py#L123
    """
    if os.name == "nt":
        import urwid

        urwid.set_encoding("utf8")
    elif assert_utf8_env:
        assert_utf8_env()
    from mitmproxy.tools import console

    run(console.master.ConsoleMaster, cmdline.mitmproxy, args)
    return None


def main(args: Optional[List[str]] = None) -> int:
    """
    Run the main program.

    This function is executed when you type `mitmproxy-image` or `python -m mitmproxy_image`.

    This is only wrapper for `mitmproxy` function.

    Arguments:
        args: Arguments passed from the command line.

    Returns:
        An exit code.
    """
    res = mitmproxy(args)
    return 0 if res is None else 1
