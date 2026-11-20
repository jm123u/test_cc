"""TraceQuarry extensions maintained separately from the upstream package.

Everything in this package is optional for the upstream pipeline. It reads the
outputs TraceQuarry already writes and is attached to the upstream code at a
small, documented set of touchpoints (see ``tq_ext/README.md``).
"""

__all__ = ["__version__"]
__version__ = "0.1.0"
