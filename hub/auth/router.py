"""Auth endpoints: wallet nonce/verify, refresh, me, session management."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db.base import get_session
from ..db.models.auth_nonce import AuthNonce
from ..db.models.auth_session_key import AuthSessionKey
from ..db.models.user import User
from . import service, session as session_svc
from .deps import get_current_user, require_session_key
from .verifiers import get_verifier

router = APIRouter(prefix="/auth", tags=["auth"])


# ── Schemas ─────────────────────────────────────────────────────────────────


class NonceRequest(BaseModel):
    address: str = Field(min_length=1)
    chain: str = Field(min_length=1)


class NonceResponse(BaseModel):
    nonce: str
    message: str
    expires_at: str
    # Authoritative `issued_at` string — clients MUST sign using this verbatim.
    # Hub rebuilds the message with the same string at /auth/verify time.
    issued_at: str


class VerifyRequest(BaseModel):
    address: str
    chain: str
    nonce: str
    signature: str
    pubkey: str
    session_pub: str
    session_scope: str = "authenticated-actions"
    session_expires_at: str  # ISO-8601


class VerifyResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    session_id: str
    init_username: Optional[str] = None


class MeResponse(BaseModel):
    id: str
    wallet_address: str
    wallet_chain: str
    init_username: Optional[str] = None


# ── Helpers ─────────────────────────────────────────────────────────────────


def _assert_chain_supported(chain: str) -> None:
    supported = {c.strip() for c in settings.AUTH_SUPPORTED_CHAINS.split(",") if c.strip()}
    if chain not in supported:
        raise HTTPException(status_code=400, detail=f"Unsupported chain: {chain}")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── Endpoints ───────────────────────────────────────────────────────────────


@router.post("/nonce", response_model=NonceResponse)
async def issue_nonce(
    body: NonceRequest,
    db: AsyncSession = Depends(get_session),
):
    _assert_chain_supported(body.chain)
    nonce = service.generate_nonce()
    expires_at = _now() + timedelta(seconds=settings.AUTH_NONCE_TTL_SECONDS)
    row = AuthNonce(
        address=body.address,
        chain=body.chain,
        nonce=nonce,
        expires_at=expires_at,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)  # pull the DB-stamped created_at back out
    issued_at_iso = row.created_at.isoformat()
    # Preview message for display — uses the same issued_at the client will
    # sign with. session_pub / session_expires_at slots remain placeholders.
    placeholder = service.build_signin_message(
        chain=body.chain,
        address=body.address,
        nonce=nonce,
        session_pub="<session_pub>",
        session_scope="authenticated-actions",
        issued_at_iso=issued_at_iso,
        session_expires_at_iso="<session_expires_at>",
    )
    return NonceResponse(
        nonce=nonce,
        message=placeholder,
        expires_at=expires_at.isoformat(),
        issued_at=issued_at_iso,
    )


@router.post("/verify", response_model=VerifyResponse)
async def verify_signature(
    body: VerifyRequest,
    response: Response,
    db: AsyncSession = Depends(get_session),
):
    _assert_chain_supported(body.chain)

    nonce_row = await db.execute(
        select(AuthNonce).where(
            AuthNonce.nonce == body.nonce,
            AuthNonce.address == body.address,
            AuthNonce.chain == body.chain,
        )
    )
    nonce_row = nonce_row.scalar_one_or_none()
    if not nonce_row or nonce_row.used_at is not None or nonce_row.expires_at <= _now():
        raise HTTPException(status_code=401, detail="Invalid or expired nonce")

    try:
        session_expires = datetime.fromisoformat(body.session_expires_at)
        if session_expires.tzinfo is None:
            session_expires = session_expires.replace(tzinfo=timezone.utc)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session_expires_at")
    if session_expires <= _now():
        raise HTTPException(status_code=400, detail="session_expires_at in the past")
    max_expiry = _now() + timedelta(seconds=settings.AUTH_SESSION_TTL_SECONDS)
    if session_expires > max_expiry:
        # Reject instead of silently clamping — any rewrite here would break
        # the client's signature (the exact string it signed must survive to
        # the rebuild below).
        raise HTTPException(
            status_code=400,
            detail=f"session_expires_at exceeds max {settings.AUTH_SESSION_TTL_SECONDS}s",
        )

    message = service.build_signin_message(
        chain=body.chain,
        address=body.address,
        nonce=body.nonce,
        session_pub=body.session_pub,
        session_scope=body.session_scope,
        issued_at_iso=nonce_row.created_at.isoformat(),
        # Verbatim — the client signed exactly this string.
        session_expires_at_iso=body.session_expires_at,
    )

    verifier = get_verifier(body.chain)
    if not verifier or not verifier(body.address, message, body.signature, body.pubkey):
        raise HTTPException(status_code=401, detail="Signature verification failed")

    nonce_row.used_at = _now()

    # Upsert user
    existing = await db.execute(
        select(User).where(
            User.wallet_address == body.address,
            User.wallet_chain == body.chain,
        )
    )
    user = existing.scalar_one_or_none()
    if user is None:
        user = User(
            wallet_address=body.address,
            wallet_chain=body.chain,
        )
        db.add(user)
        await db.flush()
        from ..vm import get_service as _get_vm_service

        await _get_vm_service().provision_for_user(db, user.id)

    sess = AuthSessionKey(
        user_id=user.id,
        session_pub=body.session_pub,
        scope=body.session_scope,
        expires_at=session_expires,
        last_nonce=0,
    )
    db.add(sess)
    await db.commit()
    await db.refresh(user)
    await db.refresh(sess)

    # Refresh token = long-lived JWT in httpOnly cookie. Rotate on every use.
    refresh_token = service.create_jwt(user.id)
    # SameSite=None required for cross-origin Vercel→Render cookie flow.
    # secure=True is mandatory when SameSite=None per spec.
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=60 * 60 * 24 * 30,
    )

    return VerifyResponse(
        access_token=service.create_jwt(user.id),
        session_id=sess.id,
        init_username=None,
    )


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: Request,
    db: AsyncSession = Depends(get_session),
):
    cookie_token = request.cookies.get("refresh_token")
    if not cookie_token:
        raise HTTPException(status_code=401, detail="Missing refresh cookie")
    try:
        user_id = service.verify_jwt(cookie_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return TokenResponse(access_token=service.create_jwt(user.id))


@router.get("/me", response_model=MeResponse)
async def me(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
):
    return MeResponse(
        id=user.id,
        wallet_address=user.wallet_address,
        wallet_chain=user.wallet_chain,
        init_username=None,
    )


@router.get("/session")
async def list_sessions(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
):
    rows = await db.execute(
        select(AuthSessionKey).where(AuthSessionKey.user_id == user.id).order_by(
            AuthSessionKey.created_at.desc()
        )
    )
    return [
        {
            "session_id": s.id,
            "scope": s.scope,
            "expires_at": s.expires_at.isoformat(),
            "revoked_at": s.revoked_at.isoformat() if s.revoked_at else None,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in rows.scalars().all()
    ]


@router.delete("/session")
async def revoke_current_session(
    response: Response,
    request: Request,
    user: User = Depends(require_session_key),
    db: AsyncSession = Depends(get_session),
):
    session_id = request.headers.get("X-Session-Id", "")
    sess = await session_svc.load_active_session(db, session_id, user.id)
    if sess:
        await session_svc.revoke_session(db, sess)
    response.delete_cookie("refresh_token")
    return {"revoked": True}


# ── API key management (unchanged) ──────────────────────────────────────────


class ApiKeyResponse(BaseModel):
    api_key: str


api_keys_router = APIRouter(prefix="/api/keys", tags=["keys"])


@api_keys_router.post("", response_model=ApiKeyResponse)
async def generate_key(
    user: User = Depends(require_session_key),
    db: AsyncSession = Depends(get_session),
):
    raw, hashed = service.generate_api_key()
    user.api_key_hash = hashed
    await db.commit()
    return ApiKeyResponse(api_key=raw)
