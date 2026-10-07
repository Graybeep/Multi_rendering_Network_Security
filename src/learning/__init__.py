"""The learning loop: cluster unrecognised lines, rank candidate fields, author a learned mapping.

Probabilistic suggestions end at a human. Nothing in this package may import from `src.rules`, write to
a canonical model, or influence a verdict; tests/test_learning.py checks the import boundary.
"""
