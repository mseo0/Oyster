"""Oyster — scanner core.

This package is the "ground truth" layer: filesystem walking, file typing,
hashing, ClamAV scanning, and process inspection. It is deliberately free of
any networking imports so it physically cannot exfiltrate data while scanning.
The only sanctioned network access lives in a separate updater component.
"""

__version__ = "0.1.0"
