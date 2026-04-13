"""Analytics engine for Spotify data analysis.

This module provides utilities for:
- Track matching and normalization
- Calculating most common tracks across playlists
- Calculating most played tracks from streaming history
- Playlist statistics and analysis
"""

from collections import Counter
from typing import Dict, List
import re


def normalize_track_key(track_name: str, artist_name: str) -> str:
    """Create normalized composite key for matching tracks.

    Normalizes track and artist names by:
    - Converting to lowercase
    - Stripping whitespace
    - Removing special characters and extra spaces

    Args:
        track_name: The track name
        artist_name: The artist name

    Returns:
        Normalized key in format "track||artist"
    """
    # Normalize track name
    track = track_name.lower().strip()
    track = re.sub(r"[^\w\s]", "", track)  # Remove special characters
    track = re.sub(r"\s+", " ", track)  # Normalize whitespace

    # Normalize artist name
    artist = artist_name.lower().strip()
    artist = re.sub(r"[^\w\s]", "", artist)
    artist = re.sub(r"\s+", " ", artist)

    return f"{track}||{artist}"


def build_track_index(playlists_data: dict) -> Dict[str, str]:
    """Build index mapping normalized track keys to URIs.

    This allows matching streaming history (which has no URI) to playlist
    tracks (which do have URI).

    Args:
        playlists_data: Raw playlists data dictionary

    Returns:
        Dictionary mapping normalized keys to track URIs
    """
    track_index = {}

    for playlist in playlists_data.get("playlists", []):
        for item in playlist.get("items", []):
            track = item.get("track")
            if track:
                uri = track.get("trackUri")
                track_name = track.get("trackName", "")
                artist_name = track.get("artistName", "")

                if uri and track_name and artist_name:
                    key = normalize_track_key(track_name, artist_name)
                    track_index[key] = uri

    return track_index


def calculate_most_common_tracks_by_playlist(
    playlists_data: dict, top_n: int = 20
) -> List[Dict]:
    """Calculate tracks that appear in the most playlists.

    Args:
        playlists_data: Raw playlists data dictionary
        top_n: Number of top tracks to return

    Returns:
        List of dicts with track_uri, track_name, artist_name, playlist_count
    """
    track_counter = Counter()
    track_info = {}

    for playlist in playlists_data.get("playlists", []):
        for item in playlist.get("items", []):
            track = item.get("track")
            if track:
                uri = track.get("trackUri")
                if uri:
                    track_counter[uri] += 1

                    # Store track info for display (only store once)
                    if uri not in track_info:
                        track_info[uri] = {
                            "name": track.get("trackName", "Unknown Track"),
                            "artist": track.get("artistName", "Unknown Artist"),
                            "album": track.get("albumName", "Unknown Album"),
                        }

    results = []
    for uri, count in track_counter.most_common(top_n):
        results.append(
            {
                "track_uri": uri,
                "track_name": track_info[uri]["name"],
                "artist_name": track_info[uri]["artist"],
                "album_name": track_info[uri]["album"],
                "playlist_count": count,
            }
        )

    return results


def calculate_most_played_tracks(
    streaming_history: List[dict], top_n: int = 20, min_ms_played: int = 30000
) -> List[Dict]:
    """Calculate most played tracks from streaming history.

    Args:
        streaming_history: List of streaming event dictionaries
        top_n: Number of top tracks to return
        min_ms_played: Minimum milliseconds played to count as a play (default 30s)

    Returns:
        List of dicts with track_name, artist_name, play_count
    """
    play_counter = Counter()

    for event in streaming_history:
        # Only count plays above minimum threshold
        ms_played = event.get("msPlayed", 0)
        if ms_played >= min_ms_played:
            track_name = event.get("trackName", "")
            artist_name = event.get("artistName", "")

            if track_name and artist_name:
                key = normalize_track_key(track_name, artist_name)
                play_counter[key] += 1

    results = []
    for key, count in play_counter.most_common(top_n):
        # Split the normalized key back into track and artist
        track_name, artist_name = key.split("||")
        results.append(
            {
                "track_name": track_name.title(),
                "artist_name": artist_name.title(),
                "play_count": count,
            }
        )

    return results


def calculate_playlist_statistics(playlists_data: dict) -> Dict:
    """Calculate overall playlist statistics.

    Args:
        playlists_data: Raw playlists data dictionary

    Returns:
        Dictionary with various playlist statistics
    """
    playlists = playlists_data.get("playlists", [])

    total_playlists = len(playlists)
    total_items = 0
    total_tracks = 0
    total_episodes = 0
    total_audiobooks = 0
    total_local_tracks = 0

    unique_track_uris = set()

    for playlist in playlists:
        items = playlist.get("items", [])
        total_items += len(items)

        for item in items:
            if item.get("track"):
                total_tracks += 1
                uri = item["track"].get("trackUri")
                if uri:
                    unique_track_uris.add(uri)
            if item.get("episode"):
                total_episodes += 1
            if item.get("audiobook"):
                total_audiobooks += 1
            if item.get("localTrack"):
                total_local_tracks += 1

    return {
        "total_playlists": total_playlists,
        "total_items": total_items,
        "total_tracks": total_tracks,
        "total_episodes": total_episodes,
        "total_audiobooks": total_audiobooks,
        "total_local_tracks": total_local_tracks,
        "unique_tracks": len(unique_track_uris),
        "avg_items_per_playlist": round(total_items / total_playlists, 1)
        if total_playlists > 0
        else 0,
    }


def match_streaming_to_playlists(
    streaming_history: List[dict], playlists_data: dict, min_ms_played: int = 30000
) -> Dict[str, int]:
    """Match streaming history events to playlist tracks.

    Returns play counts for tracks that appear in playlists.

    Args:
        streaming_history: List of streaming event dictionaries
        playlists_data: Raw playlists data dictionary
        min_ms_played: Minimum milliseconds played to count as a play

    Returns:
        Dictionary mapping track URI to play count
    """
    # Build index of normalized keys to URIs
    track_index = build_track_index(playlists_data)

    # Count plays for tracks that match playlist tracks
    uri_play_counts = Counter()

    for event in streaming_history:
        ms_played = event.get("msPlayed", 0)
        if ms_played >= min_ms_played:
            track_name = event.get("trackName", "")
            artist_name = event.get("artistName", "")

            if track_name and artist_name:
                key = normalize_track_key(track_name, artist_name)
                uri = track_index.get(key)

                if uri:
                    uri_play_counts[uri] += 1

    return dict(uri_play_counts)


def calculate_listening_time_stats(streaming_history: List[dict]) -> Dict:
    """Calculate listening time statistics.

    Args:
        streaming_history: List of streaming event dictionaries

    Returns:
        Dictionary with time-based statistics
    """
    total_ms = sum(event.get("msPlayed", 0) for event in streaming_history)
    total_events = len(streaming_history)

    # Convert to more readable units
    total_seconds = total_ms / 1000
    total_minutes = total_seconds / 60
    total_hours = total_minutes / 60
    total_days = total_hours / 24

    avg_ms_per_play = total_ms / total_events if total_events > 0 else 0
    avg_minutes_per_play = avg_ms_per_play / 60000

    return {
        "total_ms": total_ms,
        "total_seconds": round(total_seconds, 1),
        "total_minutes": round(total_minutes, 1),
        "total_hours": round(total_hours, 1),
        "total_days": round(total_days, 2),
        "total_plays": total_events,
        "avg_ms_per_play": round(avg_ms_per_play, 1),
        "avg_minutes_per_play": round(avg_minutes_per_play, 1),
    }


def get_top_artists(
    streaming_history: List[dict], top_n: int = 20, min_ms_played: int = 30000
) -> List[Dict]:
    """Get most played artists from streaming history.

    Args:
        streaming_history: List of streaming event dictionaries
        top_n: Number of top artists to return
        min_ms_played: Minimum milliseconds played to count as a play

    Returns:
        List of dicts with artist_name, play_count, total_minutes
    """
    artist_plays = Counter()
    artist_time = {}

    for event in streaming_history:
        ms_played = event.get("msPlayed", 0)
        if ms_played >= min_ms_played:
            artist_name = event.get("artistName", "")

            if artist_name:
                normalized_artist = artist_name.lower().strip()
                artist_plays[normalized_artist] += 1

                # Track total listening time per artist
                if normalized_artist not in artist_time:
                    artist_time[normalized_artist] = 0
                artist_time[normalized_artist] += ms_played

    results = []
    for artist, count in artist_plays.most_common(top_n):
        total_minutes = artist_time[artist] / 60000
        results.append(
            {
                "artist_name": artist.title(),
                "play_count": count,
                "total_minutes": round(total_minutes, 1),
            }
        )

    return results
