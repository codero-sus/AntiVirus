"""AntiVirus — a lightweight, dependency-free antivirus written in pure Python.

Features
--------
* Signature-based scanning (SHA-256 / MD5 hashes and regex patterns)
* Heuristic scanning (Shannon-entropy check for packed / encrypted files)
* Quarantine with manifest: list, restore and purge
* Directory monitoring (polling based, no external dependencies)
* JSON + human readable scan reports
* Built-in self test based on the standard, harmless EICAR test string

The project ships with the standard, *harmless* EICAR test string so you can
verify that detection works without touching any real malware.
"""

__version__ = "1.5.0"
