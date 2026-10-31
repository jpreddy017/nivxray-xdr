"""Adapter registration order matters for tie-breaking within the
same (sniff, priority) score.  Import them in declaration order so
higher-priority adapters register first."""
from . import commandline        # noqa: F401 · priority=92
from . import pdf                # noqa: F401 · priority=90
from . import docx               # noqa: F401 · priority=85 (OOXML)
from . import url as _url        # noqa: F401 · priority=82
from . import eml                # noqa: F401 · priority=80
from . import zip_archive        # noqa: F401 · priority=75
from . import html               # noqa: F401 · priority=70
from . import json_adapter       # noqa: F401 · priority=65
from . import plain_text         # noqa: F401 · priority=1  (fallback)

from ._base import adapter_registry

ADAPTERS = list(adapter_registry)
