"""
Data loading utilities with caching for Spotify data files.

The DataLoader class provides efficient loading of large JSON files with
in-memory caching to avoid repeated parsing.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from src.models import LibraryData, PlaylistsData, StreamingEvent

logger = logging.getLogger(__name__)


class DataLoader:
    """
    Handles loading and caching of Spotify data files.

    Uses in-memory caching to avoid re-parsing large JSON files.
    This is especially important for the Playlist1.json.json file (1.8MB).
    """

    def __init__(self, data_dir: Path):
        """
        Initialize the data loader.

        Args:
            data_dir: Path to directory containing Spotify data files
        """
        if isinstance(data_dir, str):
            data_dir = Path(data_dir)

        self._data_dir = data_dir
        self._cache: Dict[str, any] = {}

        # Validate data directory exists
        if not self._data_dir.exists():
            raise FileNotFoundError(f"Data directory not found: {self._data_dir}")
        if not self._data_dir.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {self._data_dir}")

        logger.info("DataLoader initialized with %s", self._data_dir)

    def load_playlists(self) -> PlaylistsData:
        """
        Load playlist data from Playlist1.json.json.

        Returns:
            PlaylistsData object containing all playlists

        Raises:
            FileNotFoundError: If the playlist file doesn't exist
            json.JSONDecodeError: If the file contains invalid JSON
        """
        cache_key = "playlists"

        if cache_key not in self._cache:
            playlist_file = self._data_dir / "Playlist1.json.json"

            if not playlist_file.exists():
                raise FileNotFoundError(f"Playlist file not found: {playlist_file}")

            logger.info("Loading playlists from %s", playlist_file)
            with open(playlist_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Validate with Pydantic model
            self._cache[cache_key] = PlaylistsData(**data)

        return self._cache[cache_key]

    def load_playlists_raw(self) -> dict:
        """
        Load raw playlist data without Pydantic validation.

        Useful for cases where you need the raw dictionary format.

        Returns:
            Raw dictionary from JSON file
        """
        cache_key = "playlists_raw"

        if cache_key not in self._cache:
            playlist_file = self._data_dir / "Playlist1.json.json"

            if not playlist_file.exists():
                raise FileNotFoundError(f"Playlist file not found: {playlist_file}")

            with open(playlist_file, "r", encoding="utf-8") as f:
                self._cache[cache_key] = json.load(f)

        return self._cache[cache_key]

    def load_streaming_history(self) -> List[StreamingEvent]:
        """
        Load streaming history from all StreamingHistory_music_*.json.json files.

        Automatically finds and loads all streaming history files matching the
        pattern StreamingHistory_music_*.json.json.

        Returns:
            List of StreamingEvent objects

        Raises:
            FileNotFoundError: If no streaming history files are found
        """
        cache_key = "streaming_history"

        if cache_key not in self._cache:
            # Find all streaming history files
            streaming_files = sorted(
                self._data_dir.glob("StreamingHistory_music_*.json.json")
            )

            if not streaming_files:
                raise FileNotFoundError(
                    f"No streaming history files found in {self._data_dir}"
                )

            logger.info(
                "Loading streaming history from %d file(s)", len(streaming_files)
            )
            all_events = []
            for file_path in streaming_files:
                with open(file_path, "r", encoding="utf-8") as f:
                    events_data = json.load(f)
                    # Validate each event with Pydantic
                    all_events.extend(
                        [StreamingEvent(**event) for event in events_data]
                    )

            self._cache[cache_key] = all_events

        return self._cache[cache_key]

    def load_streaming_history_raw(self) -> List[dict]:
        """
        Load raw streaming history without Pydantic validation.

        Returns:
            List of raw event dictionaries
        """
        cache_key = "streaming_history_raw"

        if cache_key not in self._cache:
            streaming_files = sorted(
                self._data_dir.glob("StreamingHistory_music_*.json.json")
            )

            if not streaming_files:
                raise FileNotFoundError(
                    f"No streaming history files found in {self._data_dir}"
                )

            all_events = []
            for file_path in streaming_files:
                with open(file_path, "r", encoding="utf-8") as f:
                    all_events.extend(json.load(f))

            self._cache[cache_key] = all_events

        return self._cache[cache_key]

    def load_library(self) -> LibraryData:
        """
        Load saved library from YourLibrary.json.json.

        Returns:
            LibraryData object containing all saved tracks

        Raises:
            FileNotFoundError: If the library file doesn't exist
        """
        cache_key = "library"

        if cache_key not in self._cache:
            library_file = self._data_dir / "YourLibrary.json.json"

            if not library_file.exists():
                raise FileNotFoundError(f"Library file not found: {library_file}")

            logger.info("Loading library from %s", library_file)
            with open(library_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Validate with Pydantic model
            self._cache[cache_key] = LibraryData(**data)

        return self._cache[cache_key]

    def load_library_raw(self) -> dict:
        """
        Load raw library data without Pydantic validation.

        Returns:
            Raw dictionary from JSON file
        """
        cache_key = "library_raw"

        if cache_key not in self._cache:
            library_file = self._data_dir / "YourLibrary.json.json"

            if not library_file.exists():
                raise FileNotFoundError(f"Library file not found: {library_file}")

            with open(library_file, "r", encoding="utf-8") as f:
                self._cache[cache_key] = json.load(f)

        return self._cache[cache_key]

    def clear_cache(self, key: Optional[str] = None):
        """
        Clear cached data.

        Args:
            key: Specific cache key to clear. If None, clears all cached data.
        """
        if key is None:
            self._cache.clear()
        elif key in self._cache:
            del self._cache[key]

    def get_cache_keys(self) -> List[str]:
        """
        Get list of currently cached keys.

        Returns:
            List of cache key strings
        """
        return list(self._cache.keys())

    @property
    def data_directory(self) -> Path:
        """Get the data directory path."""
        return self._data_dir
