"""
Unit tests for data loading functionality.

Tests the DataLoader class with real Spotify data files.
"""

import pytest
from pathlib import Path
from src.loaders import DataLoader
from src.models import PlaylistsData, StreamingEvent, LibraryData


@pytest.fixture
def data_loader():
    """Create a DataLoader instance for testing."""
    data_dir = Path("tests/fixture")
    return DataLoader(data_dir)


class TestDataLoader:
    """Test suite for DataLoader class."""

    def test_initialization(self):
        """Test that DataLoader initializes correctly."""
        data_dir = Path("tests/fixture")
        loader = DataLoader(data_dir)
        assert loader.data_directory == data_dir
        assert loader.get_cache_keys() == []

    def test_initialization_with_string(self):
        """Test that DataLoader accepts string paths."""
        loader = DataLoader("tests/fixture")
        assert loader.data_directory == Path("tests/fixture")

    def test_initialization_invalid_directory(self):
        """Test that DataLoader raises error for invalid directory."""
        with pytest.raises(FileNotFoundError):
            DataLoader(Path("nonexistent_directory"))

    def test_load_playlists(self, data_loader):
        """Test loading playlists with Pydantic validation."""
        playlists_data = data_loader.load_playlists()

        # Check type
        assert isinstance(playlists_data, PlaylistsData)

        # Check structure
        assert len(playlists_data.playlists) > 0
        assert hasattr(playlists_data.playlists[0], 'name')
        assert hasattr(playlists_data.playlists[0], 'items')

    def test_load_playlists_raw(self, data_loader):
        """Test loading playlists as raw dict."""
        playlists_raw = data_loader.load_playlists_raw()

        # Check type
        assert isinstance(playlists_raw, dict)
        assert 'playlists' in playlists_raw
        assert isinstance(playlists_raw['playlists'], list)

    def test_load_streaming_history(self, data_loader):
        """Test loading streaming history with Pydantic validation."""
        streaming_history = data_loader.load_streaming_history()

        # Check type
        assert isinstance(streaming_history, list)
        assert len(streaming_history) > 0
        assert isinstance(streaming_history[0], StreamingEvent)

        # Check properties
        first_event = streaming_history[0]
        assert hasattr(first_event, 'track_name')
        assert hasattr(first_event, 'artist_name')
        assert hasattr(first_event, 'ms_played')

        # Test helper properties
        assert first_event.seconds_played == first_event.ms_played / 1000.0
        assert first_event.minutes_played == first_event.ms_played / 60000.0

    def test_load_streaming_history_raw(self, data_loader):
        """Test loading streaming history as raw list."""
        streaming_raw = data_loader.load_streaming_history_raw()

        # Check type
        assert isinstance(streaming_raw, list)
        assert len(streaming_raw) > 0
        assert isinstance(streaming_raw[0], dict)

    def test_load_library(self, data_loader):
        """Test loading library with Pydantic validation."""
        library_data = data_loader.load_library()

        # Check type
        assert isinstance(library_data, LibraryData)
        assert len(library_data.tracks) > 0

        # Check structure
        first_track = library_data.tracks[0]
        assert hasattr(first_track, 'artist')
        assert hasattr(first_track, 'album')
        assert hasattr(first_track, 'track')
        assert hasattr(first_track, 'uri')

    def test_load_library_raw(self, data_loader):
        """Test loading library as raw dict."""
        library_raw = data_loader.load_library_raw()

        # Check type
        assert isinstance(library_raw, dict)
        assert 'tracks' in library_raw
        assert isinstance(library_raw['tracks'], list)

    def test_caching_behavior(self, data_loader):
        """Test that data is cached after first load."""
        # Load playlists (should cache)
        data_loader.load_playlists()
        assert 'playlists' in data_loader.get_cache_keys()

        # Load again (should use cache)
        playlists_data = data_loader.load_playlists()
        assert isinstance(playlists_data, PlaylistsData)

        # Verify cache keys
        cache_keys = data_loader.get_cache_keys()
        assert 'playlists' in cache_keys

    def test_clear_cache_specific_key(self, data_loader):
        """Test clearing specific cache key."""
        # Load and cache data
        data_loader.load_playlists()
        data_loader.load_streaming_history()

        assert len(data_loader.get_cache_keys()) >= 2

        # Clear specific key
        data_loader.clear_cache('playlists')
        assert 'playlists' not in data_loader.get_cache_keys()
        assert 'streaming_history' in data_loader.get_cache_keys()

    def test_clear_cache_all(self, data_loader):
        """Test clearing all cached data."""
        # Load and cache data
        data_loader.load_playlists()
        data_loader.load_streaming_history()
        data_loader.load_library()

        assert len(data_loader.get_cache_keys()) >= 3

        # Clear all
        data_loader.clear_cache()
        assert len(data_loader.get_cache_keys()) == 0

    def test_playlist_track_structure(self, data_loader):
        """Test that playlist tracks have correct structure."""
        playlists_data = data_loader.load_playlists()

        # Find first playlist with a track
        track_found = False
        for playlist in playlists_data.playlists:
            for item in playlist.items:
                if item.track:
                    track = item.track
                    assert hasattr(track, 'track_name')
                    assert hasattr(track, 'artist_name')
                    assert hasattr(track, 'album_name')
                    assert hasattr(track, 'track_uri')
                    assert track.track_uri.startswith('spotify:track:')
                    track_found = True
                    break
            if track_found:
                break

        assert track_found, "No tracks found in playlists"

    def test_streaming_event_time_conversions(self, data_loader):
        """Test time conversion properties on StreamingEvent."""
        streaming_history = data_loader.load_streaming_history()

        if streaming_history:
            event = streaming_history[0]

            # Test conversions
            expected_seconds = event.ms_played / 1000.0
            expected_minutes = event.ms_played / 60000.0

            assert event.seconds_played == expected_seconds
            assert event.minutes_played == expected_minutes

    def test_data_integrity(self, data_loader):
        """Test that loaded data has expected integrity."""
        # Load all data types
        playlists = data_loader.load_playlists()
        streaming = data_loader.load_streaming_history()
        library = data_loader.load_library()

        # Basic integrity checks
        assert len(playlists.playlists) > 0, "Should have at least one playlist"
        assert len(streaming) > 0, "Should have at least one streaming event"
        assert len(library.tracks) > 0, "Should have at least one library track"

        # Check for non-empty strings
        assert playlists.playlists[0].name != ""
        assert streaming[0].track_name != ""
        assert library.tracks[0].track != ""
