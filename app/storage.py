import os
import httpx

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
BUCKET = "patient-files"

def _headers(content_type: str = None):
    h = {
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "apikey": SUPABASE_KEY,
    }
    if content_type:
        h["Content-Type"] = content_type
    return h

def upload_encrypted_file(file_bytes: bytes, storage_path: str, content_type: str = "application/octet-stream") -> str:
    url = f"{SUPABASE_URL}/storage/v1/object/{BUCKET}/{storage_path}"
    response = httpx.post(url, content=file_bytes, headers=_headers(content_type))
    response.raise_for_status()
    return storage_path

def download_encrypted_file(storage_path: str) -> bytes:
    url = f"{SUPABASE_URL}/storage/v1/object/{BUCKET}/{storage_path}"
    response = httpx.get(url, headers=_headers())
    response.raise_for_status()
    return response.content

def delete_file(storage_path: str) -> None:
    url = f"{SUPABASE_URL}/storage/v1/object/{BUCKET}/{storage_path}"
    response = httpx.delete(url, headers=_headers())
    response.raise_for_status()
