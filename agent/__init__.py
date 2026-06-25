"""Agent layer: localhost-only Ollama triage + AI summary report.

This layer is the ONLY part of the app allowed to open a socket, and only ever
to 127.0.0.1:11434 (Ollama). netguard enforces that invariant.
"""
