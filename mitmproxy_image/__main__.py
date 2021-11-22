#!/usr/bin/env python
"""This script download all the image.

reference:
https://github.com/mitmproxy/mitmproxy/blob/master/examples/simple/internet_in_mirror.py
https://gist.github.com/denschub/2fcc4e03a11039616e5e6e599666f952
https://stackoverflow.com/a/44873382/1766261
"""
import argparse
import asyncio
import os
import signal
import sys
import typing

from mitmproxy import exceptions, master, options, optmanager
from mitmproxy.tools import cmdline
from mitmproxy.tools.main import assert_utf8_env, process_options
from mitmproxy.utils import arg_check, debug

from .script import MitmImage
from .version import __version__


def mitmproxy(args=None) -> typing.Optional[int]:  # pragma: no cover
    """run mitmproxy (custom).

    this is based from
    https://github.com/mitmproxy/mitmproxy/blob/1c10abef000ba2f112bc00119bcdb6707d6ff08e/mitmproxy/tools/main.py#L123
    """
    if os.name == "nt":
        import urwid

        urwid.set_encoding("utf8")
    else:
        assert_utf8_env()
    from mitmproxy.tools import console

    run(console.master.ConsoleMaster, cmdline.mitmproxy, args)
    return None


def run(
    master_cls: typing.Type[master.Master],
    make_parser: typing.Callable[[options.Options], argparse.ArgumentParser],
    arguments: typing.Sequence[str],
    extra: typing.Callable[[typing.Any], dict] = None,
) -> master.Master:  # pragma: no cover
    """
    run program.

    this is based from
    https://github.com/mitmproxy/mitmproxy/blob/1c10abef000ba2f112bc00119bcdb6707d6ff08e/mitmproxy/tools/main.py#L51

    extra: Extra argument processing callable which returns a dict of
    options.
    """
    debug.register_info_dumpers()

    opts = options.Options()
    master = master_cls(opts)

    parser = make_parser(opts)

    # To make migration from 2.x to 3.0 bearable.
    if "-R" in sys.argv and sys.argv[sys.argv.index("-R") + 1].startswith("http"):
        print("To use mitmproxy in reverse mode please use --mode reverse:SPEC instead")

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
                        "Mitmproxy-image: {}".format(__version__),
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
                master.log.info(f"Only processing flows that match \"{' & '.join(args.filter_args)}\"")
            opts.update(**extra(args))

        loop = asyncio.get_event_loop()
        ao_obj = MitmImage()
        master.addons.add(ao_obj)
        loop.create_task(ao_obj.upload_worker())
        loop.create_task(ao_obj.post_upload_worker())
        loop.create_task(ao_obj.flow_remove_worker())
        loop.create_task(ao_obj.client_worker())
        try:
            loop.add_signal_handler(signal.SIGINT, getattr(master, "prompt_for_exit", master.shutdown))
            loop.add_signal_handler(signal.SIGTERM, master.shutdown)
        except NotImplementedError:
            # Not supported on Windows
            pass

        # Make sure that we catch KeyboardInterrupts on Windows.
        # https://stackoverflow.com/a/36925722/934719
        if os.name == "nt":

            async def wakeup():
                while True:
                    await asyncio.sleep(0.2)

            asyncio.ensure_future(wakeup())

        master.run()
    except exceptions.OptionsError as e:
        print("{}: {}".format(sys.argv[0], e), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, RuntimeError):
        pass
    return master


if __name__ == "__main__":
    mitmproxy(sys.argv[1:])  # pragma: no cover
