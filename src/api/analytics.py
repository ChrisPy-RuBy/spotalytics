"""Analytics API endpoints."""

from typing import List

from fastapi import APIRouter, Depends

from src.analytics import (
    calculate_listening_time_stats,
    calculate_most_common_tracks_by_playlist,
    calculate_most_played_tracks,
    calculate_playlist_statistics,
    get_top_artists,
    match_streaming_to_playlists,
)
from src.loaders import DataLoader

router = APIRouter()


def get_data_loader() -> DataLoader:
    """Dependency to get data loader from main app."""
    from main import get_data_loader as _get

    return _get()


@router.get("/overview")
async def analytics_overview(loader: DataLoader = Depends(get_data_loader)) -> dict:
    """Get general analytics overview.

    Returns:
        Dictionary with overall statistics including:
        - Playlist statistics
        - Listening time statistics
        - Summary counts
    """
    playlists_data = loader.load_playlists_raw()
    streaming_history = loader.load_streaming_history_raw()

    playlist_stats = calculate_playlist_statistics(playlists_data)
    time_stats = calculate_listening_time_stats(streaming_history)

    return {
        "playlists": {
            "total": playlist_stats["total_playlists"],
            "total_items": playlist_stats["total_items"],
            "total_tracks": playlist_stats["total_tracks"],
            "unique_tracks": playlist_stats["unique_tracks"],
            "avg_items_per_playlist": playlist_stats["avg_items_per_playlist"],
        },
        "streaming": {
            "total_plays": time_stats["total_plays"],
            "total_hours": time_stats["total_hours"],
            "total_days": time_stats["total_days"],
            "avg_minutes_per_play": time_stats["avg_minutes_per_play"],
        },
    }


@router.get("/top-tracks-by-playlist")
async def top_tracks_by_playlist(
    limit: int = 20, loader: DataLoader = Depends(get_data_loader)
) -> List[dict]:
    """Get tracks that appear in the most playlists.

    Args:
        limit: Number of top tracks to return (default: 20)

    Returns:
        List of tracks with playlist count
    """
    playlists_data = loader.load_playlists_raw()
    return calculate_most_common_tracks_by_playlist(playlists_data, top_n=limit)


@router.get("/top-tracks-by-plays")
async def top_tracks_by_plays(
    limit: int = 20,
    min_ms_played: int = 30000,
    loader: DataLoader = Depends(get_data_loader),
) -> List[dict]:
    """Get most played tracks from streaming history.

    Args:
        limit: Number of top tracks to return (default: 20)
        min_ms_played: Minimum milliseconds to count as a play (default: 30000 = 30s)

    Returns:
        List of tracks with play count
    """
    streaming_history = loader.load_streaming_history_raw()
    return calculate_most_played_tracks(
        streaming_history, top_n=limit, min_ms_played=min_ms_played
    )


@router.get("/top-artists")
async def top_artists(
    limit: int = 20,
    min_ms_played: int = 30000,
    loader: DataLoader = Depends(get_data_loader),
) -> List[dict]:
    """Get most played artists from streaming history.

    Args:
        limit: Number of top artists to return (default: 20)
        min_ms_played: Minimum milliseconds to count as a play (default: 30000 = 30s)

    Returns:
        List of artists with play count and total listening time
    """
    streaming_history = loader.load_streaming_history_raw()
    return get_top_artists(streaming_history, top_n=limit, min_ms_played=min_ms_played)


@router.get("/playlist-stats")
async def playlist_stats(loader: DataLoader = Depends(get_data_loader)) -> dict:
    """Get detailed playlist statistics.

    Returns:
        Dictionary with comprehensive playlist statistics
    """
    playlists_data = loader.load_playlists_raw()
    return calculate_playlist_statistics(playlists_data)


@router.get("/listening-time-stats")
async def listening_time_stats(loader: DataLoader = Depends(get_data_loader)) -> dict:
    """Get listening time statistics.

    Returns:
        Dictionary with time-based statistics
    """
    streaming_history = loader.load_streaming_history_raw()
    return calculate_listening_time_stats(streaming_history)


@router.get("/matched-tracks")
async def matched_tracks(
    limit: int = 50,
    min_ms_played: int = 30000,
    loader: DataLoader = Depends(get_data_loader),
) -> dict:
    """Get tracks from playlists matched with streaming history.

    Returns streaming play counts for tracks that appear in playlists.

    Args:
        limit: Number of top matched tracks to return (default: 50)
        min_ms_played: Minimum milliseconds to count as a play (default: 30000 = 30s)

    Returns:
        Dictionary with matched track information
    """
    playlists_data = loader.load_playlists_raw()
    streaming_history = loader.load_streaming_history_raw()

    matches = match_streaming_to_playlists(
        streaming_history, playlists_data, min_ms_played=min_ms_played
    )

    # Build track info map from playlists
    track_info_map = {}
    for playlist in playlists_data.get("playlists", []):
        for item in playlist.get("items", []):
            track = item.get("track")
            if track:
                uri = track.get("trackUri")
                if uri and uri not in track_info_map:
                    track_info_map[uri] = {
                        "track_name": track.get("trackName", "Unknown"),
                        "artist_name": track.get("artistName", "Unknown"),
                        "album_name": track.get("albumName", "Unknown"),
                    }

    # Sort by play count and limit
    sorted_matches = sorted(matches.items(), key=lambda x: x[1], reverse=True)[:limit]

    results = []
    for uri, play_count in sorted_matches:
        if uri in track_info_map:
            info = track_info_map[uri]
            results.append(
                {
                    "track_uri": uri,
                    "track_name": info["track_name"],
                    "artist_name": info["artist_name"],
                    "album_name": info["album_name"],
                    "play_count": play_count,
                }
            )

    return {
        "total_matched_tracks": len(matches),
        "total_plays": sum(matches.values()),
        "tracks": results,
    }
