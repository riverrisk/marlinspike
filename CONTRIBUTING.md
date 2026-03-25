# Contributing

Thanks for contributing to MarlinSpike.

## Before You Start

- Open issues or small discussion threads are welcome for bug reports, parser gaps, UI problems, and deployment improvements.
- Keep changes focused. Small PRs are much easier to review than broad refactors.
- Avoid committing private captures, secrets, ad hoc local screenshots, or local tool metadata. Repository documentation assets under `docs/screenshots/` are the exception.

## Development Notes

- Canonical source files are `_ms_engine.py`, `_auth.py`, `_models.py`, `_config.py`, and `app.py`.
- `auth.py`, `models.py`, and `config.py` are compatibility shims only.
- The app is designed to run behind Docker Compose with PostgreSQL.

## Local Checks

Run the basic syntax check before opening a PR:

```bash
python3 -m py_compile app.py _auth.py _config.py _models.py _ms_engine.py
```

If you make Docker-related changes, also validate the stack locally:

```bash
docker compose up --build
```

## Security and Data Handling

- Do not commit secrets, `.env` files, infrastructure-specific credentials, or internal deployment notes.
- Do not commit customer captures or bundled third-party PCAP corpora unless redistribution terms are explicitly documented.
- If you find a security issue, please report it privately before opening a public issue.
