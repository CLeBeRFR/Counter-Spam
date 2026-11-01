"""Allow ``python -m counter_spam``."""

import sys

from .cli import main

sys.exit(main())
