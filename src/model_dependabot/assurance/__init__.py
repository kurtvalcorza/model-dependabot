"""Inventory assurance (feature 003): how far an inventory's claims are established.

``trust`` decides which weight-file claims need confirmation and how each claim is verified;
``format_check`` is the check source that confirms imported and legacy code-free claims from local
bytes or a bounded read of the hub file's header; ``audit`` reports findings, assurance and check
coverage for one model version from the stored data, read-only.
"""
