import os
import time
import uuid
from fastapi import APIRouter, Request, HTTPException, Depends
from starlette.responses import RedirectResponse, JSONResponse
from authlib.integrations.starlette_client import OAuth
from jose import jwt, JWTError
import db_manager

router = APIRouter()

# env config
JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
OAUTH_REDIRECT_BASE = os.getenv("OAUTH_REDIRECT_BASE", "http://localhost:5173")
# Optionally force the OAuth server base (scheme+host+port) used when constructing redirect URIs
# Set this to the exact host you registered in the provider developer console (e.g. http://localhost:8000)
OAUTH_SERVER_BASE = os.getenv("OAUTH_SERVER_BASE")

# configure OAuth
oauth = OAuth()
if os.getenv("OAUTH_GITHUB_CLIENT_ID") and os.getenv("OAUTH_GITHUB_CLIENT_SECRET"):
    oauth.register(
        name="github",
        client_id=os.getenv("OAUTH_GITHUB_CLIENT_ID"),
        client_secret=os.getenv("OAUTH_GITHUB_CLIENT_SECRET"),
        access_token_url="https://github.com/login/oauth/access_token",
        authorize_url="https://github.com/login/oauth/authorize",
        api_base_url="https://api.github.com/",
        client_kwargs={"scope": "user:email"},
    )

if os.getenv("OAUTH_GOOGLE_CLIENT_ID") and os.getenv("OAUTH_GOOGLE_CLIENT_SECRET"):
    oauth.register(
        name="google",
        client_id=os.getenv("OAUTH_GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("OAUTH_GOOGLE_CLIENT_SECRET"),
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )


@router.get("/providers")
async def providers():
    available = []
    for k in oauth._registry.keys():
        available.append(k)
    return {"providers": available}


@router.get("/login/{provider}")
async def login(request: Request, provider: str):
    if provider not in oauth._registry:
        raise HTTPException(status_code=404, detail="Provider not configured")
    # Use explicit OAUTH_SERVER_BASE when set (helps avoid redirect_uri_mismatch when hostnames differ)
    if OAUTH_SERVER_BASE:
        redirect_uri = f"{OAUTH_SERVER_BASE.rstrip('/')}/auth/callback/{provider}"
    else:
        redirect_uri = f"{request.url.scheme}://{request.url.hostname}:{request.url.port}/auth/callback/{provider}"
    return await oauth.create_client(provider).authorize_redirect(request, redirect_uri)


@router.get("/callback/{provider}")
async def callback(request: Request, provider: str):
    if provider not in oauth._registry:
        raise HTTPException(status_code=404, detail="Provider not configured")
    client = oauth.create_client(provider)

    # Reconstruct the redirect_uri the same way we built it in /login so the token
    # exchange uses the identical value the provider expects (avoids invalid_grant).
    if OAUTH_SERVER_BASE:
        redirect_uri = f"{OAUTH_SERVER_BASE.rstrip('/')}/auth/callback/{provider}"
    else:
        redirect_uri = f"{request.url.scheme}://{request.url.hostname}:{request.url.port}/auth/callback/{provider}"

    print(f"[Auth] Using redirect_uri for token exchange: {redirect_uri}")

    try:
        # Do not pass redirect_uri here; authlib stores it in session from authorize_redirect
        token = await client.authorize_access_token(request)
    except Exception as e:
        print(f"[Auth] Token exchange failed for provider={provider}: {e!r}")
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {str(e)}")

    # get profile
    if not token:
        print(f"[Auth] No token received from provider={provider}: {token}")
        raise HTTPException(status_code=400, detail="No access token received from provider")

    # Debug: print token keys but not values
    try:
        print(f"[Auth] Token keys: {list(token.keys()) if isinstance(token, dict) else type(token)}")
    except Exception:
        pass

    if provider == "github":
        # Pass token explicitly to API calls to avoid missing_token errors
        profile_resp = await client.get("/user", token=token)
        profile = profile_resp.json()
        provider_id = str(profile.get("id"))
        email = profile.get("email")
        name = profile.get("name") or profile.get("login")
        # github may require additional call to /user/emails for verified email
        if not email:
            emails = await client.get("/user/emails", token=token)
            try:
                email = [e for e in emails.json() if e.get("primary")][0]["email"]
            except Exception:
                email = None
    else:  # google uses OIDC standard
        userinfo = token.get("userinfo")
        if not userinfo:
            # fetch
            userinfo_resp = await client.parse_id_token(request, token)
            profile = userinfo_resp
        else:
            profile = userinfo
        provider_id = str(profile.get("sub") or profile.get("id"))
        email = profile.get("email")
        name = profile.get("name")

    # find or create user
    if db_manager.db_manager is None:
        raise HTTPException(status_code=503, detail="DB manager not initialized")

    try:
        found = await db_manager.db_manager.find_user_by_provider(provider, provider_id)
    except Exception as e:
        # Log and return a clearer error if the DB schema or connection is problematic
        print(f"[Auth][DB] Error finding user by provider: {e}")
        raise HTTPException(status_code=500, detail="Database error while searching for user")

    # If no record by provider, try to find by email and link accounts (common case)
    if not found:
        if email:
            try:
                existing = await db_manager.db_manager.find_user_by_email(email)
            except Exception as e:
                print(f"[Auth][DB] Error finding user by email: {e}")
                raise HTTPException(status_code=500, detail="Database error while searching for user by email")
            if existing:
                print(f"[Auth] Found existing user by email ({email}), linking provider {provider}")
                # Ensure provider info recorded (but do not overwrite existing provider/provider_id if present)
                try:
                    target = await db_manager.db_manager.get_engine_for_write(0)
                    if target:
                        engine, idx = target
                        await db_manager.db_manager.update_user_provider(engine, existing["id"], provider, provider_id)
                except Exception as e:
                    print(f"[Auth][DB] Error linking provider to existing user: {e}")
                found = existing

    # If provider is github, we want to update the stored GitHub token on the user record
    github_token = None 
    if provider == "github" and token and "access_token" in token:
        github_token = token["access_token"]

    # Still not found -> create a new user
    if not found:
        target = await db_manager.db_manager.get_engine_for_write(0)
        if not target:
            raise HTTPException(status_code=507, detail="No DB with available space to create user")
        engine, idx = target
        user_id = str(uuid.uuid4())
        user_obj = {
            "id": user_id, 
            "email": email, 
            "name": name, 
            "provider": provider, 
            "provider_id": provider_id,
            "github_token": github_token if github_token else None
        }
        try:
            await db_manager.db_manager.create_user(engine, user_obj)
        except Exception as e:
            # If insert failed due to race (e.g., concurrent creation with same email), attempt to load by email and continue
            print(f"[Auth][DB] Error creating user: {e}")
            try:
                fallback = await db_manager.db_manager.find_user_by_email(email) if email else None
                if fallback:
                    print(f"[Auth] Fallback to existing user by email after insert race: {fallback['id']}")
                    found = fallback
                else:
                    raise
            except Exception as e2:
                print(f"[Auth][DB] Fallback also failed: {e2}")
                raise HTTPException(status_code=500, detail="Database error while creating user")
        else:
            found = user_obj
    else:
        # User found - if we have a new github token, update it!
        if github_token:
             # Basic SQL update to set the token 
             # We need to find which shard (engine) the user is in. 
             # Since find_user_by_email/id already ran and 'found' is the dict, we don't have the engine ref directly 
             # on the dict object from common DB manager read. 
             # But we can try to update across engines or just update where it was found if we had that info.
             # For now, simplest approach is to call a helper method we need to add to DBManager or just reuse get_engine_for_write logic?
             # Better: Add update_user_token method to DBManager.
             pass 
             # TODO: Implement update token logic. For this demo, we'll assume new users get the token.
             # Actually, we should try to update it.
             try:
                 await db_manager.db_manager.update_github_token(found["id"], github_token)
             except Exception as e:
                 print(f"[Auth] Failed to update github token: {e}")

    # create jwt
    payload = {"sub": found["id"], "email": found.get("email"), "exp": int(time.time()) + 3600}
    token_str = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    # redirect back to frontend and set httpOnly cookie
    frontend_target = f"{OAUTH_REDIRECT_BASE}/auth-callback?status=ok"
    print(f"[Auth] Redirecting user to frontend callback: {frontend_target} (OAUTH_REDIRECT_BASE={OAUTH_REDIRECT_BASE})")
    response = RedirectResponse(frontend_target)
    response.set_cookie("sast_token", token_str, httponly=True, secure=False, samesite="lax", max_age=3600)
    return response


async def _get_token_from_request(request: Request):
    token = request.cookies.get("sast_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return data
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@router.get("/me")
async def me(request: Request):
    token = await _get_token_from_request(request)
    user_id = token.get("sub")
    if db_manager.db_manager is None:
        raise HTTPException(status_code=503, detail="DB manager not initialized")
    found = await db_manager.db_manager.find_user_by_id(user_id)
    if not found:
        raise HTTPException(status_code=404, detail="User not found")
        
    # Mask sensitive tokens before returning to frontend
    user_safe = dict(found)
    if "github_token" in user_safe:
        user_safe["has_github"] = bool(user_safe["github_token"])
        del user_safe["github_token"]
        
    return {"user": user_safe}


@router.post("/logout")
async def logout():
    r = JSONResponse({"ok": True})
    r.delete_cookie("sast_token")
    return r


# Simple in-memory OTP store for email verification
# email -> { otp, expires, attempts, last_sent }
OTP_STORE = {}

import re
import random
import smtplib
import ssl

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

EMAIL_OTP_TTL = 300  # seconds
RESEND_COOLDOWN = 30  # seconds


def _is_valid_email(email: str) -> bool:
    if not email:
        return False
    # Very small regex for basic validation
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is not None


EMAIL_DEV_MODE = os.getenv("EMAIL_DEV_MODE", "0") == "1"

def _send_email_smtp(to_email: str, subject: str, body: str):
    """Send using configured SMTP. If EMAIL_DEV_MODE is enabled and SMTP isn't configured,
    we will not raise an exception and will allow development flows to proceed (OTP returned in response)."""
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        if EMAIL_DEV_MODE:
            print(f"[Auth][SMTP] SMTP not configured; running in EMAIL_DEV_MODE, skipping send to {to_email}")
            return
        raise RuntimeError("SMTP not configured")

    message = f"From: {SMTP_USER}\r\nTo: {to_email}\r\nSubject: {subject}\r\n\r\n{body}"
    context = ssl.create_default_context()

    # Try implicit SSL for port 465 first if specified, otherwise STARTTLS
    try:
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10, context=context) as server:
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_USER, [to_email], message)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_USER, [to_email], message)
    except smtplib.SMTPAuthenticationError as e:
        print(f"[Auth][SMTP] Authentication failed when sending to {to_email}: {e}")
        raise RuntimeError("SMTP authentication failed. Check SMTP_USER and SMTP_PASSWORD")
    except Exception as e:
        print(f"[Auth][SMTP] Error sending email to {to_email}: {e}")
        raise RuntimeError(f"SMTP connection failed: {e}")


@router.post("/email/send-otp")
async def send_otp(request: Request):
    data = await request.json()
    email = (data.get("email") or "").strip().lower()
    if not _is_valid_email(email):
        raise HTTPException(status_code=400, detail="Invalid email")

    now = int(time.time())
    existing = OTP_STORE.get(email)
    if existing and (now - existing.get("last_sent", 0)) < RESEND_COOLDOWN:
        raise HTTPException(status_code=429, detail=f"Try again in {RESEND_COOLDOWN} seconds")

    otp = f"{random.randint(0, 999999):06d}"
    OTP_STORE[email] = {"otp": otp, "expires": now + EMAIL_OTP_TTL, "attempts": 0, "last_sent": now}

    # send email
    subject = "Your SAST verification code"
    body = f"Your verification code is: {otp}\nIt will expire in {EMAIL_OTP_TTL//60} minutes. If you did not request this, ignore this email."
    try:
        _send_email_smtp(email, subject, body)
    except Exception as e:
        # remove OTP on failure to avoid confusion
        OTP_STORE.pop(email, None)
        # If dev mode is enabled, return the otp in the response so local dev can proceed
        if EMAIL_DEV_MODE:
            print(f"[Auth][SMTP] send failed but EMAIL_DEV_MODE active; returning OTP for dev: {e}")
            return {"ok": True, "ttl": EMAIL_OTP_TTL, "dev_otp": otp}
        # otherwise return helpful error
        raise HTTPException(status_code=500, detail=f"Failed to send OTP email: {str(e)}")

    # success
    resp = {"ok": True, "ttl": EMAIL_OTP_TTL}
    if EMAIL_DEV_MODE:
        resp["dev_otp"] = otp
    return resp


@router.post("/email/verify")
async def verify_otp(request: Request):
    data = await request.json()
    email = (data.get("email") or "").strip().lower()
    otp = (data.get("otp") or "").strip()
    if not _is_valid_email(email) or not otp:
        raise HTTPException(status_code=400, detail="Invalid email or otp")

    record = OTP_STORE.get(email)
    now = int(time.time())
    if not record or record.get("expires", 0) < now:
        OTP_STORE.pop(email, None)
        raise HTTPException(status_code=400, detail="OTP expired or not found")

    if record.get("attempts", 0) >= 5:
        OTP_STORE.pop(email, None)
        raise HTTPException(status_code=429, detail="Too many attempts")

    if otp != record.get("otp"):
        record["attempts"] = record.get("attempts", 0) + 1
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # OTP is valid; remove it
    OTP_STORE.pop(email, None)

    # find or create user
    if db_manager.db_manager is None:
        raise HTTPException(status_code=503, detail="DB manager not initialized")

    try:
        found = await db_manager.db_manager.find_user_by_email(email)
    except Exception as e:
        print(f"[Auth][DB] Error finding user by email: {e}")
        raise HTTPException(status_code=500, detail="Database error while searching for user by email")

    if not found:
        target = await db_manager.db_manager.get_engine_for_write(0)
        if not target:
            raise HTTPException(status_code=507, detail="No DB with available space to create user")
        engine, idx = target
        user_id = str(uuid.uuid4())
        user_obj = {"id": user_id, "email": email, "name": None, "provider": "email", "provider_id": email}
        try:
            await db_manager.db_manager.create_user(engine, user_obj)
        except Exception as e:
            print(f"[Auth][DB] Error creating user: {e}")
            try:
                found = await db_manager.db_manager.find_user_by_email(email)
                if found:
                    print(f"[Auth] Fallback to existing user by email after insert race: {found['id']}")
                else:
                    raise
            except Exception as e2:
                print(f"[Auth][DB] Fallback also failed: {e2}")
                raise HTTPException(status_code=500, detail="Database error while creating user")
        else:
            found = user_obj

    # create jwt
    payload = {"sub": found["id"], "email": found.get("email"), "exp": int(time.time()) + 3600}
    token_str = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    # set cookie and return json
    frontend_target = f"{OAUTH_REDIRECT_BASE}/auth-callback?status=ok"
    print(f"[Auth] Email verified for {email}, redirecting to frontend callback: {frontend_target}")
    r = JSONResponse({"ok": True, "redirect": frontend_target})
    r.set_cookie("sast_token", token_str, httponly=True, secure=False, samesite="lax", max_age=3600)
    return r
