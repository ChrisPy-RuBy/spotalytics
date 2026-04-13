"""Spotify Data Tool - FastAPI Web Application.

A web application for visualizing and exploring Spotify data with interactive
charts and dashboards.
"""

import logging
import tempfile
import zipfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from src.auth import verify_session_cookie

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.api import analytics, playlists, tracks
from src.app_state import AppState

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB

# Application state — replaces the old global DataLoader singleton
app_state = AppState()


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Clean up uploaded data when the server shuts down."""
    yield
    logger.info("Server shutting down, cleaning up uploaded data")
    app_state.reset()


# Initialize FastAPI app
app = FastAPI(
    title="Spotify Data Tool",
    description="Visualize and explore your Spotify data",
    version="0.1.0",
    lifespan=lifespan,
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Configure Jinja2 templates
templates = Jinja2Templates(directory="src/templates")

def get_data_loader():
    """Get the DataLoader from app state, or raise if no data is loaded."""
    if not app_state.is_loaded:
        raise HTTPException(status_code=403, detail="No data loaded")
    return app_state.loader


# Middleware: redirect to /upload when no data is loaded
UPLOAD_ALLOWED_PREFIXES = ("/upload", "/static", "/api/", "/health", "/sign-in")


@app.middleware("http")
async def require_data(request: Request, call_next):
    """Redirect to upload page if no data has been loaded yet."""
    if not app_state.is_loaded and not any(
        request.url.path.startswith(p) for p in UPLOAD_ALLOWED_PREFIXES
    ):
        return RedirectResponse(url="/upload")
    return await call_next(request)


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code},
    )


@app.exception_handler(FileNotFoundError)
async def file_not_found_handler(request: Request, exc: FileNotFoundError):
    """Handle file not found errors."""
    logger.error("Data file not found: %s", exc)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Data file not found. Please ensure data files are in the 'data' directory.",
            "detail": str(exc),
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions."""
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "error": "An unexpected error occurred",
            "detail": str(exc),
            "type": type(exc).__name__,
        },
    )


_auth = [Depends(verify_session_cookie)]

# Include API routers
app.include_router(playlists.router, prefix="/api/playlists", tags=["playlists"], dependencies=_auth)
app.include_router(tracks.router, prefix="/api/tracks", tags=["tracks"], dependencies=_auth)
app.include_router(analytics.router, prefix="/api/analytics", tags=["analytics"], dependencies=_auth)


# Upload endpoint
@app.post("/api/upload", dependencies=_auth)
async def upload_spotify_data(file: UploadFile):
    """Accept a Spotify data export zip file, validate, extract, and load it."""
    # Read file contents and check size
    contents = await file.read()
    logger.info("Upload received: %s (%d bytes)", file.filename, len(contents))
    if len(contents) > MAX_UPLOAD_SIZE:
        logger.warning("Upload rejected: file too large (%d bytes)", len(contents))
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {MAX_UPLOAD_SIZE // (1024 * 1024)}MB.",
        )

    # Write to a temporary file so zipfile can work with it
    tmp_zip = Path(tempfile.mktemp(suffix=".zip"))
    try:
        tmp_zip.write_bytes(contents)

        if not zipfile.is_zipfile(tmp_zip):
            logger.warning("Upload rejected: not a valid zip archive")
            raise HTTPException(
                status_code=400, detail="Uploaded file is not a valid zip archive."
            )

        with zipfile.ZipFile(tmp_zip, "r") as zf:
            # Check for path traversal
            for name in zf.namelist():
                if ".." in name or name.startswith("/"):
                    logger.warning("Upload rejected: unsafe path %r", name)
                    raise HTTPException(
                        status_code=400,
                        detail=f"Zip contains unsafe path: {name}",
                    )

            # Validate required files (may be nested in a subdirectory)
            playlist_entry = None
            for name in zf.namelist():
                if name == "Playlist1.json.json" or name.endswith(
                    "/Playlist1.json.json"
                ):
                    playlist_entry = name
                    break

            if playlist_entry is None:
                logger.warning("Upload rejected: missing Playlist1.json.json")
                raise HTTPException(
                    status_code=400,
                    detail="Invalid Spotify export: missing Playlist1.json.json",
                )

            # Extract to a temporary directory
            extract_dir = Path(tempfile.mkdtemp(prefix="spotify_data_"))
            zf.extractall(extract_dir)

    finally:
        tmp_zip.unlink(missing_ok=True)

    # Point DataLoader at the directory containing the data files
    data_dir = extract_dir / Path(playlist_entry).parent
    app_state.load_from_directory(data_dir, extract_root=extract_dir)

    logger.info("Upload successful: data loaded from %s", data_dir)
    return RedirectResponse(url="/", status_code=303)


# Reset endpoint
@app.post("/api/reset", dependencies=_auth)
async def reset_data():
    """Clear the current dataset and redirect to the upload page."""
    logger.info("Data reset requested")
    app_state.reset()
    return RedirectResponse(url="/upload", status_code=303)


# Page routes
@app.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    """Upload page — shown when no data is loaded."""
    return templates.TemplateResponse("upload.html", {"request": request})


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Home page / dashboard."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/playlists", response_class=HTMLResponse)
async def playlists_page(request: Request):
    """Playlists browsing page."""
    return templates.TemplateResponse("playlists.html", {"request": request})


@app.get("/tracks", response_class=HTMLResponse)
async def tracks_page(request: Request):
    """Tracks browsing page."""
    return templates.TemplateResponse("tracks.html", {"request": request})


@app.get("/analytics", response_class=HTMLResponse)
async def analytics_page(request: Request):
    """Analytics dashboard page."""
    return templates.TemplateResponse("analytics.html", {"request": request})


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "spotify-data-tool"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
            "main:app", 
            host="0.0.0.0",
            port=8100,
            loop="uvloop",
            http="httptools",
            proxy_headers=True,
            )

