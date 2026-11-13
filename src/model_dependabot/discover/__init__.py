"""Dependency discovery (feature 003): candidate dependencies proposed from a project folder.

Discovery reads only inside the project, within published limits, and never runs project code,
imports model code or deserialises weights. It never opens a ``Store``, so it reads and writes no
database (FR-022); the integration tests check that no database file is created.
"""
