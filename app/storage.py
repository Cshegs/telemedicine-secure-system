import os
from supabase import create_client, Client

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
BUCKET = "patient-files"

def get_supabase() -> Client:
    return create_client(SUPABASE_URL, SUPABASE_KEY)

def upload_encrypted_file(
    file_bytes: bytes,
    storage_path: str,
    content_type: str = "application/octet-stream"
) -> str:
    """Upload encrypted bytes to Supabase Storage. Returns the storage path."""
    client = get_supabase()
    client.storage.from_(BUCKET).upload(
        path=storage_path,
        file=file_bytes,
        file_options={"content-type": content_type, "upsert": "true"}
    )
    return storage_path

def download_encrypted_file(storage_path: str) -> bytes:
    """Download encrypted bytes from Supabase Storage."""
    client = get_supabase()
    response = client.storage.from_(BUCKET).download(storage_path)
    return response

def delete_file(storage_path: str) -> None:
    """Delete a file from Supabase Storage."""
    client = get_supabase()
    client.storage.from_(BUCKET).remove([storage_path])
