"""Crackbaby internal modules package.

Single source of truth for install-relative directories used across the
codebase.  Defined here (not per-module) so every importer agrees regardless of
where it physically lives in the package.

``realpath`` follows symlinks, so when crackbaby is invoked through a symlink such
as ``/usr/local/bin/crackbaby -> /opt/crackbaby/crackbaby.py`` these still resolve to
the real install root (``/opt/crackbaby``), not the symlink's directory.
"""

import os

# Install root = the directory that contains both ``crackbaby.py`` and this
# ``modules/`` package (i.e. the parent of this file's directory).
CRACKBABY_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

# Per-install configuration directory — contains both the shipped sample templates
# (*.json.sample, git-tracked) and the user's live config files (*.json, gitignored):
#   crackbaby.json        user config (copy from crackbaby.json.sample and edit)
#   speed_factors.json    per-rig speed ratios (auto-generated, user-tunable)
CONFIG_DIR = os.path.join(CRACKBABY_ROOT, "config")
