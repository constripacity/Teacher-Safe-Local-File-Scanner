# Absolute import: PyInstaller freezes this file as the top-level ``__main__``
# script, which has no parent package, so a relative ``from .main`` raises
# "attempted relative import with no known parent package" in the frozen binary.
# The absolute form works both here and under ``python -m scanner``.
from scanner.main import main

if __name__ == "__main__":  # pragma: no cover - package entry point
    import sys

    sys.exit(main())
