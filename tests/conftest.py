"""Keep the test suite off the real account.

obsideo_core.config reads OBSIDEO_CONFIG_DIR (default ~/.obsideo) and loads
its credentials into the environment at import. Without this, a test run
inherits whoever is logged in on the machine, and anything a test lets
through to the config directory (e.g. the bucket marker) lands in the real
one. Set before any obsideo module is imported.
"""

import os
import tempfile

for _k in [k for k in os.environ if k.upper().startswith("OBSIDEO_")]:
    del os.environ[_k]
os.environ["OBSIDEO_CONFIG_DIR"] = tempfile.mkdtemp(prefix="obsideo-tests-")
