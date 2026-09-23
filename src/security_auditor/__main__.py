"""Module execution delegates to the packaged CLI."""

from .cli.main import main

raise SystemExit(main())
