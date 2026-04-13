"""Playlists API endpoints."""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException

from src.loaders import DataLoader

router = APIRouter()


def get_data_loader() -> DataLoader:
    """Dependency to get data loader from main app."""
    from main import get_data_loader as _get

    return _get()


@router.get("/")
async def list_playlists(
    limit: Optional[int] = None,
    offset: int = 0,
    loader: DataLoader = Depends(get_data_loader),
) -> dict:
    """List all playlists.

    Args:
        limit: Maximum number of playlists to return (optional)
        offset: Number of playlists to skip (default: 0)

    Returns:
        Dictionary with playlists and metadata
    """
    playlists_data = loader.load_playlists_raw()
    all_playlists = playlists_data.get("playlists", [])

    # Apply offset and limit
    total = len(all_playlists)
    playlists_slice = all_playlists[offset:]
    if limit:
        playlists_slice = playlists_slice[:limit]

    # Build summary for each playlist
    summaries = []
    for playlist in playlists_slice:
        items = playlist.get("items", [])
        track_count = sum(1 for item in items if item.get("track"))
        episode_count = sum(1 for item in items if item.get("episode"))
        local_count = sum(1 for item in items if item.get("localTrack"))

        summaries.append(
            {
                "name": playlist.get("name", "Untitled"),
                "last_modified_date": playlist.get("lastModifiedDate", "Unknown"),
                "total_items": len(items),
                "track_count": track_count,
                "episode_count": episode_count,
                "local_track_count": local_count,
            }
        )

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "count": len(summaries),
        "playlists": summaries,
    }


@router.get("/{playlist_name}")
async def get_playlist(
    playlist_name: str,
    include_tracks: bool = True,
    loader: DataLoader = Depends(get_data_loader),
) -> dict:
    """Get details for a specific playlist by name.

    Args:
        playlist_name: Name of the playlist
        include_tracks: Whether to include full track details (default: True)

    Returns:
        Playlist details with optional track information

    Raises:
        HTTPException: If playlist not found
    """
    playlists_data = loader.load_playlists_raw()
    all_playlists = playlists_data.get("playlists", [])

    # Find playlist by name
    playlist = None
    for p in all_playlists:
        if p.get("name") == playlist_name:
            playlist = p
            break

    if not playlist:
        raise HTTPException(
            status_code=404, detail=f"Playlist '{playlist_name}' not found"
        )

    items = playlist.get("items", [])

    result = {
        "name": playlist.get("name", "Untitled"),
        "last_modified_date": playlist.get("lastModifiedDate", "Unknown"),
        "total_items": len(items),
    }

    if include_tracks:
        tracks = []
        for item in items:
            track = item.get("track")
            if track:
                tracks.append(
                    {
                        "track_uri": track.get("trackUri"),
                        "track_name": track.get("trackName", "Unknown"),
                        "artist_name": track.get("artistName", "Unknown"),
                        "album_name": track.get("albumName", "Unknown"),
                        "added_date": item.get("addedDate", "Unknown"),
                    }
                )

        result["tracks"] = tracks
        result["track_count"] = len(tracks)

    return result


@router.get("/search/by-name")
async def search_playlists_by_name(
    query: str, loader: DataLoader = Depends(get_data_loader)
) -> List[dict]:
    """Search playlists by name.

    Args:
        query: Search query string

    Returns:
        List of matching playlists
    """
    playlists_data = loader.load_playlists_raw()
    all_playlists = playlists_data.get("playlists", [])

    query_lower = query.lower()
    matching_playlists = []

    for playlist in all_playlists:
        name = playlist.get("name", "")
        if query_lower in name.lower():
            items = playlist.get("items", [])
            track_count = sum(1 for item in items if item.get("track"))

            matching_playlists.append(
                {
                    "name": name,
                    "last_modified_date": playlist.get("lastModifiedDate", "Unknown"),
                    "total_items": len(items),
                    "track_count": track_count,
                }
            )

    return matching_playlists
