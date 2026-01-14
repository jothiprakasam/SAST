"""clear_neon.py

Safely truncate or drop all tables on all configured Neon/Postgres shards.

Usage:
  python scripts/clear_neon.py --dry-run               # list tables and counts on each shard
  python scripts/clear_neon.py --execute --yes        # actually truncate all tables on every shard
  python scripts/clear_neon.py --drop --execute --yes # drop all tables instead of truncating

IMPORTANT SAFETY: This script is destructive. It requires either interactive confirmation
or the explicit --yes flag together with --execute to perform changes.

It uses the project's DB manager environment setup (make_manager_from_env) so it will
operate on the same shards the application is configured to use.
"""

import asyncio
import argparse
import sys
import os
from pathlib import Path
from dotenv import load_dotenv
from sqlalchemy import text

# When running this script directly from scripts/ or elsewhere, ensure the project root
# is on sys.path so we can import project modules like `db_manager`.
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

# Try to load a .env file from the project root (useful for local dev)
_env_path = repo_root.joinpath('.env')
if _env_path.exists():
    try:
        load_dotenv(str(_env_path))
    except Exception:
        pass

try:
    import db_manager
except Exception as e:
    print(f"[clear_neon] ERROR: failed to import db_manager from project root {repo_root}: {e}")
    raise


async def list_tables_and_counts(engine):
    tables = []
    async with engine.connect() as conn:
        # Fetch user tables from public schema
        r = await conn.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'"))
        rows = r.fetchall()
        tables = [row[0] for row in rows]
        counts = {}
        for t in tables:
            try:
                cr = await conn.execute(text(f'SELECT COUNT(*) FROM "{t}"'))
                counts[t] = int(cr.scalar() or 0)
            except Exception:
                counts[t] = None
    return tables, counts


async def truncate_tables(engine, tables):
    if not tables:
        return
    quoted = ', '.join(f'"{t}"' for t in tables)
    stmt = text(f'TRUNCATE TABLE {quoted} RESTART IDENTITY CASCADE')
    async with engine.begin() as conn:
        await conn.execute(stmt)


async def drop_tables(engine, tables):
    if not tables:
        return
    quoted = ', '.join(f'"{t}"' for t in tables)
    stmt = text(f'DROP TABLE IF EXISTS {quoted} CASCADE')
    async with engine.begin() as conn:
        await conn.execute(stmt)


async def main():
    parser = argparse.ArgumentParser(description='Clear all data from Neon/Postgres shards configured in env')
    parser.add_argument('--dry-run', action='store_true', help='Print tables and row counts, do not modify')
    parser.add_argument('--execute', action='store_true', help='Execute the destructive operation (requires confirmation)')
    parser.add_argument('--drop', action='store_true', help='Drop tables instead of truncating them')
    parser.add_argument('--yes', action='store_true', help='Non-interactive confirmation (use with --execute)')
    parser.add_argument('--db-urls', type=str, help='Comma-separated database URLs (overrides NEON_DBS/URLS env var)')
    args = parser.parse_args()

    # Ensure environment variables from project .env are loaded (if any)
    try:
        # load_dotenv was called at module import if a .env file was present; re-run to capture shell changes
        load_dotenv()
    except Exception:
        pass

    print('[clear_neon] Initializing DB manager...')

    # If env vars are present, show a short confirmation to the user
    env_urls = os.getenv('URLS') or os.getenv('NEON_DBS')
    if env_urls:
        print('[clear_neon] Found DB URLs in environment (URLS/NEON_DBS).')

    # Allow explicit DB URLs on the command line for one-off usage
    if args.db_urls:
        url_list = [u.strip() for u in args.db_urls.split(',') if u.strip()]
        if not url_list:
            print('[clear_neon] ERROR: --db-urls provided but no valid URLs parsed.')
            sys.exit(2)
        mgr = db_manager.DBManager(url_list)
    else:
        try:
            mgr = db_manager.make_manager_from_env()
        except Exception as e:
            print(f"[clear_neon] ERROR: {e}")
            print("Provide DB URLs via NEON_DBS/URLS env var or use --db-urls CLI option.")
            sys.exit(2)

    if mgr is None:
        print('[clear_neon] ERROR: DB manager initialization failed')
        sys.exit(2)

    await mgr.init_engines()

    if not mgr.engines:
        print('[clear_neon] No database engines available.')
        sys.exit(2)

    all_tables = []

    for idx, engine in enumerate(mgr.engines):
        print(f'\n[clear_neon] Shard {idx}: connecting...')
        try:
            tables, counts = await list_tables_and_counts(engine)
        except Exception as e:
            print(f'[clear_neon] Failed to list tables on shard {idx}: {e}')
            tables, counts = [], {}

        print(f'[clear_neon] Found {len(tables)} tables on shard {idx}:')
        for t in tables:
            cnt = counts.get(t)
            cnt_str = str(cnt) if cnt is not None else 'N/A'
            print(f'  - {t}: {cnt_str} rows')

        all_tables.append((idx, engine, tables, counts))

    if args.dry_run or not args.execute:
        print('\n[clear_neon] Dry-run mode (no changes made).')
        print('Run with --execute --yes to perform the action, or re-run with --drop to drop tables.')
        return

    # Confirm destructive action
    if not args.yes:
        print('\n[clear_neon] You are about to {} all tables on ALL configured shards.'.format('DROP' if args.drop else 'TRUNCATE'))
        confirm = input('Type DELETE to confirm: ')
        if confirm.strip() != 'DELETE':
            print('Confirmation failed. Aborting.')
            return

    # Execute
    for idx, engine, tables, counts in all_tables:
        if not tables:
            print(f'[clear_neon] Shard {idx}: no tables to operate on.')
            continue
        try:
            action = 'DROP' if args.drop else 'TRUNCATE'
            print(f'[clear_neon] Shard {idx}: performing {action} on {len(tables)} tables...')
            if args.drop:
                await drop_tables(engine, tables)
            else:
                await truncate_tables(engine, tables)
            print(f'[clear_neon] Shard {idx}: completed {action}.')
        except Exception as e:
            print(f'[clear_neon] Shard {idx}: operation failed: {e}')

    print('\n[clear_neon] All requested operations completed.')
    print('[clear_neon] Done.')


if __name__ == '__main__':
    asyncio.run(main())