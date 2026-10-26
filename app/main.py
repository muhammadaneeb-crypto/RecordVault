from datetime import date, datetime, timezone
from uuid import UUID, uuid4
from typing import Optional
import os

from fastapi import FastAPI, Depends, HTTPException, Header, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from supabase import create_client, Client


from .config import settings

app = FastAPI(title="RecordVault API", version="1.0.0")

origins = [x.strip() for x in settings.allowed_origins.split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins != ["*"] else ["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

supabase: Client = create_client(settings.supabase_url, settings.supabase_service_role_key)

ALLOWED_IMAGE_TYPES = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}

class RecordCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    id_card_number: str = Field(min_length=1, max_length=40)
    record_date: date

class RecordUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=150)
    id_card_number: Optional[str] = Field(default=None, min_length=1, max_length=40)
    record_date: Optional[date] = None

def get_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer access token.")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Empty access token.")
    try:
        result = supabase.auth.get_user(token)
        user = getattr(result, "user", None)
        if not user or not getattr(user, "id", None):
            raise HTTPException(status_code=401, detail="Invalid or expired access token.")
        return {"id": str(user.id), "email": getattr(user, "email", None)}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired access token.")

def owned_record(record_id: str, owner_id: str) -> dict:
    try:
        result = supabase.table("records").select("*").eq("id", record_id).eq("owner_id", owner_id).maybe_single().execute()
        data = result.data
    except Exception:
        data = None
    if not data:
        raise HTTPException(status_code=404, detail="Record not found.")
    return data

def image_rows(record_id: str, owner_id: str) -> list:
    result = supabase.table("record_images").select("*").eq("record_id", record_id).eq("owner_id", owner_id).order("created_at").execute()
    return result.data or []

@app.get("/health")
def health():
    return {"status": "ok", "service": "RecordVault API"}

@app.get("/auth/me")
def me(user: dict = Depends(get_user)):
    return {"id": user["id"], "email": user["email"]}

@app.post("/records", status_code=201)
def create_record(payload: RecordCreate, user: dict = Depends(get_user)):
    row = {
        "owner_id": user["id"],
        "name": payload.name.strip(),
        "id_card_number": payload.id_card_number.strip(),
        "record_date": payload.record_date.isoformat(),
    }
    try:
        result = supabase.table("records").insert(row).execute()
        return result.data[0]
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Could not create record. Check database schema and input.") from exc

@app.get("/records")
def list_records(search: str = Query(default="", max_length=100), user: dict = Depends(get_user)):
    try:
        query = supabase.table("records").select("*").eq("owner_id", user["id"]).order("created_at", desc=True)
        # Search is restricted to the current user's already-filtered query.
        if search.strip():
            safe = search.strip().replace("%", "").replace(",", "")
            query = query.or_(f"name.ilike.%{safe}%,id_card_number.ilike.%{safe}%")
        result = query.execute()
        return {"items": result.data or []}
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Could not fetch records.") from exc

@app.get("/records/{record_id}")
def get_record(record_id: UUID, user: dict = Depends(get_user)):
    record = owned_record(str(record_id), user["id"])
    record["images"] = image_rows(str(record_id), user["id"])
    return record

@app.patch("/records/{record_id}")
def update_record(record_id: UUID, payload: RecordUpdate, user: dict = Depends(get_user)):
    owned_record(str(record_id), user["id"])
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="No changes supplied.")
    if "name" in changes and changes["name"] is not None:
        changes["name"] = changes["name"].strip()
    if "id_card_number" in changes and changes["id_card_number"] is not None:
        changes["id_card_number"] = changes["id_card_number"].strip()
    if "record_date" in changes and changes["record_date"] is not None:
        changes["record_date"] = changes["record_date"].isoformat()
    changes["updated_at"] = datetime.now(timezone.utc).isoformat()
    result = supabase.table("records").update(changes).eq("id", str(record_id)).eq("owner_id", user["id"]).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Record not found.")
    return result.data[0]

@app.post("/records/{record_id}/images", status_code=201)
async def upload_image(record_id: UUID, file: UploadFile = File(...), user: dict = Depends(get_user)):
    rid = str(record_id)
    owned_record(rid, user["id"])
    content_type = (file.content_type or "").lower()
    if content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(status_code=415, detail="Only JPEG, PNG, and WebP images are allowed.")
    data = await file.read(settings.max_image_bytes + 1)
    if not data:
        raise HTTPException(status_code=400, detail="Empty image.")
    if len(data) > settings.max_image_bytes:
        raise HTTPException(status_code=413, detail=f"Image exceeds {settings.max_image_bytes // (1024*1024)} MB limit.")
    # Basic signature check prevents trusting only the client-provided MIME type.
    valid = (
        (content_type == "image/jpeg" and data.startswith(b"\xff\xd8\xff")) or
        (content_type == "image/png" and data.startswith(b"\x89PNG\r\n\x1a\n")) or
        (content_type == "image/webp" and len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP")
    )
    if not valid:
        raise HTTPException(status_code=415, detail="File content does not match an allowed image type.")
    path = f'{user["id"]}/{rid}/{uuid4().hex}{ALLOWED_IMAGE_TYPES[content_type]}'
    try:
        supabase.storage.from_(settings.storage_bucket).upload(
            path, data, {"content-type": content_type, "upsert": "false"}
        )
        inserted = supabase.table("record_images").insert({
            "record_id": rid, "owner_id": user["id"], "storage_path": path
        }).execute()
        return inserted.data[0]
    except Exception as exc:
        # Best-effort cleanup if metadata insertion fails after upload.
        try:
            supabase.storage.from_(settings.storage_bucket).remove([path])
        except Exception:
            pass
        raise HTTPException(status_code=400, detail="Image upload failed. Check private bucket and database setup.") from exc

@app.get("/records/{record_id}/images")
def list_images(record_id: UUID, user: dict = Depends(get_user)):
    rid = str(record_id)
    owned_record(rid, user["id"])
    rows = image_rows(rid, user["id"])
    output = []
    for row in rows:
        try:
            signed = supabase.storage.from_(settings.storage_bucket).create_signed_url(row["storage_path"], 60)
            signed_url = signed.get("signedURL") or signed.get("signedUrl")
            if signed_url and signed_url.startswith("/"):
                signed_url = settings.supabase_url.rstrip("/") + "/storage/v1" + signed_url
            output.append({**row, "signed_url": signed_url})
        except Exception:
            output.append({**row, "signed_url": None})
    return {"items": output}

@app.delete("/records/{record_id}/images/{image_id}")
def delete_image(record_id: UUID, image_id: UUID, user: dict = Depends(get_user)):
    rid, iid = str(record_id), str(image_id)
    owned_record(rid, user["id"])
    result = supabase.table("record_images").select("*").eq("id", iid).eq("record_id", rid).eq("owner_id", user["id"]).maybe_single().execute()
    row = result.data
    if not row:
        raise HTTPException(status_code=404, detail="Image not found.")
    try:
        supabase.storage.from_(settings.storage_bucket).remove([row["storage_path"]])
        supabase.table("record_images").delete().eq("id", iid).eq("owner_id", user["id"]).execute()
        return {"status": "deleted"}
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Could not delete image.") from exc

@app.delete("/records/{record_id}")
def delete_record(record_id: UUID, user: dict = Depends(get_user)):
    rid = str(record_id)
    owned_record(rid, user["id"])
    rows = image_rows(rid, user["id"])
    paths = [row["storage_path"] for row in rows]
    try:
        if paths:
            supabase.storage.from_(settings.storage_bucket).remove(paths)
        supabase.table("record_images").delete().eq("record_id", rid).eq("owner_id", user["id"]).execute()
        supabase.table("records").delete().eq("id", rid).eq("owner_id", user["id"]).execute()
        return {"status": "deleted"}
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Could not fully delete record. Retry or check storage.") from exc
