# Spotalytics

A FastAPI web application for exploring and analysing the data export that Spotify provides to its users. Upload your Spotify data dump and browse your playlists, tracks, and listening analytics through a web interface.

## Features

- **Playlist browser** — view all playlists with track listings
- **Track browser** — explore your saved library
- **Analytics dashboard** — most common tracks by playlist appearances and by play count

## Requirements

- Python 3.13+
- [uv](https://docs.astral.sh/uv/) for dependency management

## Getting started

Install dependencies:

```bash
uv sync
```

Run the development server:

```bash
python main.py
```

The app will be available at `http://localhost:8000`.

## Running tests

```bash
uv run pytest
```

## Project structure

```
main.py                  # Application entry point
src/
  loaders.py             # Spotify data file parsing
  models.py              # Data models
  analytics.py           # Analytics computations
  api/                   # FastAPI route handlers
    playlists.py
    tracks.py
    analytics.py
  templates/             # Jinja2 HTML templates
    base.html
    index.html
    playlists.html
    tracks.html
    analytics.html
static/                  # CSS and JS assets
tests/                   # Automated test suite
docs/                    # Planning and development notes
```
