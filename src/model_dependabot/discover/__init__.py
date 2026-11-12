"""Dependency discovery (feature 003): candidate dependencies proposed from a project folder.

Discovery reads only inside the project, within published limits, and never runs project code,
imports model code or deserialises weights. It never imports ``model_dependabot.store``, so it
cannot open the tool's database: that it opens none is a fact of the package, not a convention.
"""
