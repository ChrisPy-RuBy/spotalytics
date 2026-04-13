# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

Spotalytics — a FastAPI web application for exploring Spotify data exports. Users upload their Spotify data dump and browse playlists, tracks, and listening analytics in a web UI.

## Key Commands

```bash
uv sync                 # Install dependencies
python main.py          # Run dev server (localhost:8000)
uv run pytest           # Run test suite
```

Pre-commit hooks run Ruff for linting and formatting on staged files.

## Dependencies

Runtime: FastAPI, Uvicorn, Jinja2, python-multipart
Dev: pytest, pre-commit, httpx

## Code Structure

- `main.py` — entry point, creates the FastAPI app and mounts routes/static files
- `src/loaders.py` — parses Spotify JSON data files (playlists, streaming history, library)
- `src/models.py` — data models
- `src/analytics.py` — analytics computations (top tracks by playlist, by play count)
- `src/api/` — FastAPI route handlers (`playlists.py`, `tracks.py`, `analytics.py`)
- `src/templates/` — Jinja2 templates (`base.html`, `index.html`, `playlists.html`, `tracks.html`, `analytics.html`)
- `static/` — CSS and JS assets
- `tests/` — automated tests (`test_loaders.py`, `test_analytics.py`)
- `docs/` — planning and development notes

## Conventions

- Use `uv` for all dependency management (never pip)
- Tests go in `tests/` and are run with pytest
- Ruff handles linting and formatting via pre-commit
