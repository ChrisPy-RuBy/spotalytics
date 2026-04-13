"""
Pydantic models for Spotify data structures.

These models handle data validation and type conversion for the various
Spotify data export formats.
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List


# ============================================================================
# Playlist Models
# ============================================================================


class PlaylistTrack(BaseModel):
    """Track information from playlist data."""

    model_config = ConfigDict(populate_by_name=True)

    track_name: str = Field(alias="trackName")
    artist_name: str = Field(alias="artistName")
    album_name: str = Field(alias="albumName")
    track_uri: str = Field(alias="trackUri")


class PlaylistItem(BaseModel):
    """Item in a playlist (can be track, episode, audiobook, or local track)."""

    model_config = ConfigDict(populate_by_name=True)

    track: Optional[PlaylistTrack] = None
    episode: Optional[dict] = None  # Could expand this later if needed
    audiobook: Optional[dict] = None  # Could expand this later if needed
    local_track: Optional[dict] = Field(default=None, alias="localTrack")
    added_date: str = Field(alias="addedDate")


class Playlist(BaseModel):
    """A Spotify playlist with metadata and items."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    last_modified_date: str = Field(alias="lastModifiedDate")
    collaborators: List[str] = []
    items: List[PlaylistItem] = []


class PlaylistsData(BaseModel):
    """Root structure for Playlist1.json.json file."""

    playlists: List[Playlist]


# ============================================================================
# Streaming History Models
# ============================================================================


class StreamingEvent(BaseModel):
    """A single streaming event from listening history."""

    model_config = ConfigDict(populate_by_name=True)

    end_time: str = Field(alias="endTime")
    artist_name: str = Field(alias="artistName")
    track_name: str = Field(alias="trackName")
    ms_played: int = Field(alias="msPlayed")

    @property
    def seconds_played(self) -> float:
        """Convert milliseconds to seconds."""
        return self.ms_played / 1000.0

    @property
    def minutes_played(self) -> float:
        """Convert milliseconds to minutes."""
        return self.ms_played / 60000.0


# ============================================================================
# Library Models
# ============================================================================


class LibraryTrack(BaseModel):
    """Track from user's saved library."""

    artist: str
    album: str
    track: str
    uri: str


class LibraryData(BaseModel):
    """Root structure for YourLibrary.json.json file."""

    tracks: List[LibraryTrack]


# ============================================================================
# API Response Models (for FastAPI endpoints)
# ============================================================================


class PlaylistSummary(BaseModel):
    """Summary information about a playlist for API responses."""

    name: str
    track_count: int
    last_modified: str


class TrackInfo(BaseModel):
    """Unified track information for API responses."""

    track_name: str
    artist_name: str
    album_name: Optional[str] = None
    track_uri: Optional[str] = None


class TopTrackByPlaylist(BaseModel):
    """Track ranked by playlist appearance count."""

    track_uri: str
    track_name: str
    artist_name: str
    playlist_count: int


class TopTrackByPlays(BaseModel):
    """Track ranked by play count from streaming history."""

    track_name: str
    artist_name: str
    play_count: int


class AnalyticsOverview(BaseModel):
    """High-level statistics for the dashboard."""

    total_playlists: int
    total_playlist_items: int
    total_streams: int
    unique_tracks_in_playlists: Optional[int] = None
    unique_tracks_in_history: Optional[int] = None
