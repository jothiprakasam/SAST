import os
import asyncio
from typing import List, Optional, Tuple
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine
from sqlalchemy import text


class DBManager:
    def __init__(self, urls: List[str], threshold_bytes: int = 500 * 1024 * 1024):
        # Prepare URLs for asyncpg dialect: remove unsupported query params (sslmode, channel_binding)
        from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

        self.urls = []
        self._connect_args = []  # parallel list to hold connect_args per url
        for u in urls:
            # detect ssl requirement
            ssl_required = False
            if "sslmode=require" in u:
                ssl_required = True
            parts = urlsplit(u)
            qs = dict(parse_qsl(parts.query))
            # remove params unsupported by asyncpg connect
            qs.pop("sslmode", None)
            qs.pop("channel_binding", None)
            new_query = urlencode(qs)
            cleaned = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
            async_url = cleaned.replace("postgresql://", "postgresql+asyncpg://", 1)
            self.urls.append(async_url)
            connect_args = {}
            if ssl_required:
                try:
                    import ssl
                    connect_args["ssl"] = ssl.create_default_context()
                except Exception:
                    connect_args["ssl"] = True
            self._connect_args.append(connect_args)

        self.threshold = threshold_bytes
        self.engines: List[AsyncEngine] = []

    async def init_engines(self):
        for url, conn_args in zip(self.urls, self._connect_args):
            # Increase connection timeout if possible via connect_args or query
            # For asyncpg, we can pass command_timeout in connect_args if needed, 
            # but connection timeout is usually handled differently.
            engine = create_async_engine(url, pool_pre_ping=True, connect_args=conn_args)
            self.engines.append(engine)
        
        # quick ping
        print(f"[DB] Initializing {len(self.engines)} database connections...")
        for i, engine in enumerate(self.engines):
            try:
                async with engine.connect() as conn:
                    await conn.execute(text("SELECT 1"))
                print(f"[DB] Connection {i} established.")
            except Exception as e:
                print(f"[DB] WARNING: Failed to connect to database {i}: {e}")
                print("[DB] The server will start, but DB-dependent features (saving scans, login) may fail.")

    async def get_db_sizes(self) -> List[int]:
        sizes = []
        for engine in self.engines:
            try:
                async with engine.connect() as conn:
                    r = await conn.execute(text("SELECT pg_database_size(current_database())"))
                    val = r.scalar() or 0
                    sizes.append(int(val))
            except Exception:
                sizes.append(2**62)
        return sizes

    async def get_engine_for_write(self, required_bytes: int = 0) -> Optional[Tuple[AsyncEngine, int]]:
        sizes = await self.get_db_sizes()
        for engine, size, idx in zip(self.engines, sizes, range(len(self.engines))):
            if size + required_bytes < self.threshold:
                return engine, idx
        return None

    async def ensure_tables(self):
        create_users = """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT,
            name TEXT,
            provider TEXT,
            provider_id TEXT,
            github_token TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
        );
        """
        
        # Migration for existing tables
        try:
             # Try to add the column if it doesn't exist (SQLite/Postgres specific syntax handling might be needed but simple ADD COLUMN usually works)
             # For asyncpg/sqlalchemy we execute raw SQL
             for engine in self.engines:
                 async with engine.begin() as conn:
                     try:
                        await conn.execute(text("ALTER TABLE users ADD COLUMN github_token TEXT"))
                     except Exception:
                        pass # Column likely exists or table doesn't exist yet
        except:
            pass

        create_files = """
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            owner_id TEXT,
            storage_db TEXT,
            metadata JSONB,
            size BIGINT,
            content BYTEA,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
        );
        """

        create_scans = """
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            owner_id TEXT,
            project_path TEXT,
            results JSONB,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
        );
        """

        for i, engine in enumerate(self.engines):
            try:
                async with engine.begin() as conn:
                    await conn.execute(text(create_users))
                    await conn.execute(text(create_files))
                    await conn.execute(text(create_scans))

                    # Defensive migration: ensure commonly expected columns are present so
                    # older DBs without recent schema changes won't break the app.
                    await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT"))
                    await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT"))
                    await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS provider TEXT"))
                    await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS provider_id TEXT"))
                    await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now()"))
                    
                    # Ensure files table has content column
                    await conn.execute(text("ALTER TABLE files ADD COLUMN IF NOT EXISTS content BYTEA"))

            except Exception as e:
                print(f"[DB] WARNING: Failed to ensure tables on database {i}: {e}")
                print("[DB] Skipping schema setup for this shard.")

    async def find_user_by_provider(self, provider: str, provider_id: str):
        for engine in self.engines:
            async with engine.connect() as conn:
                r = await conn.execute(
                    text("SELECT id, email, name, provider, provider_id FROM users WHERE provider = :p AND provider_id = :pid LIMIT 1"),
                    {"p": provider, "pid": provider_id},
                )
                row = r.first()
                if row:
                    return dict(row._mapping)
        return None

    async def find_user_by_email(self, email: str):
        """Find a user by email (useful to link accounts across providers)."""
        if not email:
            return None
        for engine in self.engines:
            async with engine.connect() as conn:
                r = await conn.execute(
                    text("SELECT id, email, name, provider, provider_id FROM users WHERE email = :email LIMIT 1"),
                    {"email": email},
                )
                row = r.first()
                if row:
                    return dict(row._mapping)
        return None

    async def update_user_provider(self, engine: AsyncEngine, user_id: str, provider: str, provider_id: str):
        """Set provider/provider_id for an existing user if not already set.
        This avoids overwriting provider info unintentionally when linking accounts.
        """
        async with engine.begin() as conn:
            await conn.execute(
                text("UPDATE users SET provider = COALESCE(provider, :provider), provider_id = COALESCE(provider_id, :provider_id) WHERE id = :id"),
                {"provider": provider, "provider_id": provider_id, "id": user_id},
            )

    async def update_github_token(self, user_id: str, token: str):
         """Updates user's github token across all shards (where the user exists)"""
         for engine in self.engines:
             async with engine.begin() as conn:
                 await conn.execute(
                     text("UPDATE users SET github_token = :token WHERE id = :id"),
                     {"token": token, "id": user_id}
                 )

    async def find_user_by_id(self, user_id: str):
        for engine in self.engines:
            async with engine.connect() as conn:
                # Include github_token in selection
                r = await conn.execute(
                    text("SELECT id, email, name, provider, provider_id, github_token FROM users WHERE id = :id LIMIT 1"), {"id": user_id}
                )
                row = r.first()
                if row:
                    return dict(row._mapping)
        return None

    async def create_user(self, engine: AsyncEngine, user: dict):
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO users (id, email, name, provider, provider_id, github_token) VALUES (:id, :email, :name, :provider, :provider_id, :github_token)"),
                user,
            )

    async def insert_file(self, engine: AsyncEngine, file_data: dict):
        async with engine.begin() as conn:
            # We use distinct params for content to ensure it is handled as binary if needed by driver
            await conn.execute(
                text("INSERT INTO files (id, owner_id, storage_db, metadata, size, content) VALUES (:id, :owner_id, :storage_db, CAST(:metadata AS jsonb), :size, :content)"),
                file_data,
            )

    async def get_file(self, file_id: str):
        for engine in self.engines:
            async with engine.connect() as conn:
                # We select content only when needed. CAUTION: content can be large.
                r = await conn.execute(text("SELECT id, owner_id, storage_db, metadata, size, content, created_at FROM files WHERE id = :id LIMIT 1"), {"id": file_id})
                row = r.first()
                if row:
                    return dict(row._mapping)
        return None

    async def insert_scan(self, engine: AsyncEngine, metadata: dict):
        async with engine.begin() as conn:
            # Use explicit CAST() to bind :results reliably (avoids mixing positional and named params with asyncpg)
            await conn.execute(
                text("INSERT INTO scans (id, owner_id, project_path, results) VALUES (:id, :owner_id, :project_path, CAST(:results AS jsonb))"),
                {
                    "id": metadata.get("id"),
                    "owner_id": metadata.get("owner_id"),
                    "project_path": metadata.get("project_path"),
                    "results": metadata.get("results"),
                },
            )

    async def list_scans(self, owner_id: Optional[str] = None) -> list:
        rows = []
        for engine in self.engines:
            async with engine.connect() as conn:
                if owner_id:
                    stmt = text("SELECT id, owner_id, project_path, created_at, results FROM scans WHERE owner_id = :owner_id ORDER BY created_at DESC")
                    params = {"owner_id": owner_id}
                else:
                    stmt = text("SELECT id, owner_id, project_path, created_at, results FROM scans ORDER BY created_at DESC")
                    params = {}
                
                r = await conn.execute(stmt, params)
                for row in r.fetchall():
                    rows.append(dict(row._mapping))
        # sort by created_at desc across DBs
        rows.sort(key=lambda r: r.get("created_at") or "", reverse=True)
        return rows

    async def get_scan(self, scan_id: str):
        for engine in self.engines:
            async with engine.connect() as conn:
                r = await conn.execute(text("SELECT id, owner_id, project_path, created_at, results FROM scans WHERE id = :id LIMIT 1"), {"id": scan_id})
                row = r.first()
                if row:
                    return dict(row._mapping)
        return None

# Helper singleton created from URLS env variable by server startup
db_manager: Optional[DBManager] = None


def make_manager_from_env():
    global db_manager
    urls = os.getenv("URLS") or os.getenv("NEON_DBS")
    if not urls:
        raise RuntimeError("No NEON DB URLs provided in URLS or NEON_DBS env var")
    url_list = [u.strip() for u in urls.split(",") if u.strip()]
    db_manager = DBManager(url_list)
    return db_manager
