# Contributing to Teacher-Safe Local File Scanner

Thanks for keeping classrooms secure! Before submitting a contribution, please review these guidelines.

## Code of conduct

Be respectful. This project focuses on defensive security education—no offensive tooling.

## Getting started

1. Fork the repository and create a feature branch (`git checkout -b feature/your-change`).
2. Install dependencies: `pip install -r requirements.txt` (and `requirements-optional.txt` if needed).
3. Run the test suite and linters before committing.

## Coding standards

- Follow PEP 8 and keep functions well-documented with docstrings and type hints.
- Prefer the Python standard library; optional defensive packages must be feature-flagged.
- Use pathlib for path manipulation and never execute untrusted content.

## Pull request checklist

- [ ] Tests (`pytest`) pass locally.
- [ ] Linting (`ruff check .`) passes.
- [ ] Documentation updated (README, SAFETY, CHANGELOG as appropriate).
- [ ] New code includes logging where useful and avoids executing untrusted inputs.

## Release process

Releases are tracked in `CHANGELOG.md`. Update the file and bump the version in `scanner/__init__.py` and `pyproject.toml` when preparing a release.
