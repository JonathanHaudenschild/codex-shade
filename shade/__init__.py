"""shade — keep personal data and credentials out of an AI agent's context.

Pure standard library, no network calls, no services to run.
"""

__version__ = "0.5.0"

from .engine import Engine, Finding, summarize  # noqa: F401
