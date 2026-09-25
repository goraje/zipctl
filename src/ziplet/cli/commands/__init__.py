"""The ``ziplet`` subcommands, one module each.

Every module exposes ``register(subparsers)``, which adds its parser and binds
the handler, so a command's arguments and behaviour live side by side.  What
only commands share lives in :mod:`ziplet.cli.commands.helpers`; so does what
a single command needs beyond its handler (``collect`` and ``create_report`` for
``create``, ``extract_report`` for ``extract``), to keep one module per command.
"""
