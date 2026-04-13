"""Unit tests for analytics module."""

import pytest
from src.analytics import (
    normalize_track_key,
    build_track_index,
    calculate_most_common_tracks_by_playlist,
    calculate_most_played_tracks,
    calculate_playlist_statistics,
    match_streaming_to_playlists,
    calculate_listening_time_stats,
    get_top_artists,
)


class TestNormalizeTrackKey:
    """Tests for track normalization."""

    def test_basic_normalization(self):
        """Test basic track key normalization."""
        key = normalize_track_key("Bohemian Rhapsody", "Queen")
        assert key == "bohemian rhapsody||queen"

    def test_case_insensitive(self):
        """Test that normalization is case insensitive."""
        key1 = normalize_track_key("Hello", "Adele")
        key2 = normalize_track_key("HELLO", "ADELE")
        key3 = normalize_track_key("hElLo", "AdElE")
        assert key1 == key2 == key3

    def test_whitespace_handling(self):
        """Test whitespace stripping and normalization."""
        key = normalize_track_key("  Track  Name  ", "  Artist  Name  ")
        assert key == "track name||artist name"

    def test_special_characters_removed(self):
        """Test that special characters are removed."""
        key = normalize_track_key("Song (Remix)", "Artist & Friends")
        assert key == "song remix||artist friends"

    def test_empty_strings(self):
        """Test handling of empty strings."""
        key = normalize_track_key("", "")
        assert key == "||"


class TestBuildTrackIndex:
    """Tests for track index building."""

    @pytest.fixture
    def sample_playlists_data(self):
        """Sample playlists data for testing."""
        return {
            "playlists": [
                {
                    "name": "Playlist 1",
                    "items": [
                        {
                            "track": {
                                "trackUri": "spotify:track:123",
                                "trackName": "Song A",
                                "artistName": "Artist 1",
                            }
                        },
                        {
                            "track": {
                                "trackUri": "spotify:track:456",
                                "trackName": "Song B",
                                "artistName": "Artist 2",
                            }
                        },
                    ],
                },
                {
                    "name": "Playlist 2",
                    "items": [
                        {
                            "track": {
                                "trackUri": "spotify:track:123",
                                "trackName": "Song A",
                                "artistName": "Artist 1",
                            }
                        }
                    ],
                },
            ]
        }

    def test_build_index(self, sample_playlists_data):
        """Test building track index."""
        index = build_track_index(sample_playlists_data)

        assert len(index) == 2
        assert "song a||artist 1" in index
        assert "song b||artist 2" in index
        assert index["song a||artist 1"] == "spotify:track:123"
        assert index["song b||artist 2"] == "spotify:track:456"

    def test_empty_playlists(self):
        """Test with empty playlists data."""
        index = build_track_index({"playlists": []})
        assert len(index) == 0

    def test_missing_track_data(self):
        """Test handling of missing track data."""
        data = {
            "playlists": [
                {
                    "items": [
                        {"track": None},
                        {"track": {"trackUri": "spotify:track:123"}},  # Missing names
                        {"episode": {"episodeName": "Episode 1"}},  # Not a track
                    ]
                }
            ]
        }
        index = build_track_index(data)
        assert len(index) == 0


class TestCalculateMostCommonTracksByPlaylist:
    """Tests for calculating most common tracks."""

    @pytest.fixture
    def sample_playlists_data(self):
        """Sample playlists with repeated tracks."""
        return {
            "playlists": [
                {
                    "name": "Playlist 1",
                    "items": [
                        {
                            "track": {
                                "trackUri": "spotify:track:AAA",
                                "trackName": "Popular Song",
                                "artistName": "Artist A",
                                "albumName": "Album 1",
                            }
                        },
                        {
                            "track": {
                                "trackUri": "spotify:track:BBB",
                                "trackName": "Other Song",
                                "artistName": "Artist B",
                                "albumName": "Album 2",
                            }
                        },
                    ],
                },
                {
                    "name": "Playlist 2",
                    "items": [
                        {
                            "track": {
                                "trackUri": "spotify:track:AAA",
                                "trackName": "Popular Song",
                                "artistName": "Artist A",
                                "albumName": "Album 1",
                            }
                        }
                    ],
                },
                {
                    "name": "Playlist 3",
                    "items": [
                        {
                            "track": {
                                "trackUri": "spotify:track:AAA",
                                "trackName": "Popular Song",
                                "artistName": "Artist A",
                                "albumName": "Album 1",
                            }
                        }
                    ],
                },
            ]
        }

    def test_most_common_tracks(self, sample_playlists_data):
        """Test calculating most common tracks."""
        results = calculate_most_common_tracks_by_playlist(
            sample_playlists_data, top_n=10
        )

        assert len(results) == 2
        assert results[0]["track_uri"] == "spotify:track:AAA"
        assert results[0]["playlist_count"] == 3
        assert results[0]["track_name"] == "Popular Song"
        assert results[0]["artist_name"] == "Artist A"

        assert results[1]["track_uri"] == "spotify:track:BBB"
        assert results[1]["playlist_count"] == 1

    def test_limit_results(self, sample_playlists_data):
        """Test limiting number of results."""
        results = calculate_most_common_tracks_by_playlist(
            sample_playlists_data, top_n=1
        )
        assert len(results) == 1

    def test_empty_playlists(self):
        """Test with empty playlists."""
        results = calculate_most_common_tracks_by_playlist({"playlists": []})
        assert len(results) == 0


class TestCalculateMostPlayedTracks:
    """Tests for calculating most played tracks."""

    @pytest.fixture
    def sample_streaming_history(self):
        """Sample streaming history data."""
        return [
            {
                "trackName": "Song X",
                "artistName": "Artist X",
                "msPlayed": 180000,  # 3 minutes
            },
            {"trackName": "Song X", "artistName": "Artist X", "msPlayed": 200000},
            {"trackName": "Song Y", "artistName": "Artist Y", "msPlayed": 150000},
            {
                "trackName": "Song Z",
                "artistName": "Artist Z",
                "msPlayed": 10000,  # Only 10 seconds - should be filtered
            },
        ]

    def test_most_played_tracks(self, sample_streaming_history):
        """Test calculating most played tracks."""
        results = calculate_most_played_tracks(sample_streaming_history, top_n=10)

        assert len(results) == 2  # Song Z filtered out
        assert results[0]["track_name"] == "Song X"
        assert results[0]["artist_name"] == "Artist X"
        assert results[0]["play_count"] == 2

        assert results[1]["track_name"] == "Song Y"
        assert results[1]["play_count"] == 1

    def test_minimum_play_threshold(self, sample_streaming_history):
        """Test minimum play time threshold."""
        results = calculate_most_played_tracks(
            sample_streaming_history,
            top_n=10,
            min_ms_played=160000,  # 2:40
        )

        # Only Song X's plays should count (180s and 200s)
        assert len(results) == 1
        assert results[0]["track_name"] == "Song X"
        assert results[0]["play_count"] == 2

    def test_empty_history(self):
        """Test with empty streaming history."""
        results = calculate_most_played_tracks([])
        assert len(results) == 0


class TestCalculatePlaylistStatistics:
    """Tests for playlist statistics."""

    @pytest.fixture
    def sample_playlists_data(self):
        """Sample playlists with various item types."""
        return {
            "playlists": [
                {
                    "name": "Mixed Playlist",
                    "items": [
                        {
                            "track": {
                                "trackUri": "spotify:track:1",
                                "trackName": "Song 1",
                            }
                        },
                        {
                            "track": {
                                "trackUri": "spotify:track:2",
                                "trackName": "Song 2",
                            }
                        },
                        {"episode": {"episodeName": "Episode 1"}},
                        {
                            "track": {
                                "trackUri": "spotify:track:1",
                                "trackName": "Song 1",
                            }
                        },  # Duplicate
                    ],
                },
                {
                    "name": "Tracks Only",
                    "items": [
                        {
                            "track": {
                                "trackUri": "spotify:track:3",
                                "trackName": "Song 3",
                            }
                        },
                        {
                            "track": {
                                "trackUri": "spotify:track:4",
                                "trackName": "Song 4",
                            }
                        },
                    ],
                },
            ]
        }

    def test_playlist_statistics(self, sample_playlists_data):
        """Test calculating playlist statistics."""
        stats = calculate_playlist_statistics(sample_playlists_data)

        assert stats["total_playlists"] == 2
        assert stats["total_items"] == 6
        assert stats["total_tracks"] == 5
        assert stats["total_episodes"] == 1
        assert stats["unique_tracks"] == 4  # Duplicate track counted once
        assert stats["avg_items_per_playlist"] == 3.0

    def test_empty_playlists(self):
        """Test with no playlists."""
        stats = calculate_playlist_statistics({"playlists": []})
        assert stats["total_playlists"] == 0
        assert stats["avg_items_per_playlist"] == 0


class TestMatchStreamingToPlaylists:
    """Tests for matching streaming history to playlists."""

    @pytest.fixture
    def sample_data(self):
        """Sample playlists and streaming history."""
        playlists = {
            "playlists": [
                {
                    "items": [
                        {
                            "track": {
                                "trackUri": "spotify:track:111",
                                "trackName": "Matched Song",
                                "artistName": "Matched Artist",
                            }
                        }
                    ]
                }
            ]
        }

        streaming = [
            {
                "trackName": "Matched Song",
                "artistName": "Matched Artist",
                "msPlayed": 180000,
            },
            {
                "trackName": "Matched Song",
                "artistName": "Matched Artist",
                "msPlayed": 200000,
            },
            {
                "trackName": "Unmatched Song",
                "artistName": "Unknown Artist",
                "msPlayed": 150000,
            },
        ]

        return playlists, streaming

    def test_match_streaming_to_playlists(self, sample_data):
        """Test matching streaming history to playlist tracks."""
        playlists, streaming = sample_data
        matches = match_streaming_to_playlists(streaming, playlists)

        assert "spotify:track:111" in matches
        assert matches["spotify:track:111"] == 2  # Played twice
        assert len(matches) == 1  # Only one matched track


class TestCalculateListeningTimeStats:
    """Tests for listening time statistics."""

    def test_listening_time_stats(self):
        """Test calculating listening time statistics."""
        history = [
            {"msPlayed": 180000},  # 3 minutes
            {"msPlayed": 240000},  # 4 minutes
            {"msPlayed": 300000},  # 5 minutes
        ]

        stats = calculate_listening_time_stats(history)

        assert stats["total_ms"] == 720000
        assert stats["total_minutes"] == 12.0
        assert stats["total_hours"] == 0.2
        assert stats["total_plays"] == 3
        assert stats["avg_minutes_per_play"] == 4.0

    def test_empty_history(self):
        """Test with empty history."""
        stats = calculate_listening_time_stats([])
        assert stats["total_ms"] == 0
        assert stats["total_plays"] == 0
        assert stats["avg_ms_per_play"] == 0


class TestGetTopArtists:
    """Tests for top artists calculation."""

    @pytest.fixture
    def sample_streaming_history(self):
        """Sample streaming history for artist analysis."""
        return [
            {"artistName": "Artist A", "msPlayed": 180000},
            {"artistName": "Artist A", "msPlayed": 200000},
            {"artistName": "Artist B", "msPlayed": 150000},
            {"artistName": "Artist A", "msPlayed": 120000},
        ]

    def test_top_artists(self, sample_streaming_history):
        """Test getting top artists."""
        results = get_top_artists(sample_streaming_history, top_n=10)

        assert len(results) == 2
        assert results[0]["artist_name"] == "Artist A"
        assert results[0]["play_count"] == 3
        assert results[0]["total_minutes"] == pytest.approx(8.33, rel=0.1)

        assert results[1]["artist_name"] == "Artist B"
        assert results[1]["play_count"] == 1

    def test_limit_results(self, sample_streaming_history):
        """Test limiting number of results."""
        results = get_top_artists(sample_streaming_history, top_n=1)
        assert len(results) == 1
