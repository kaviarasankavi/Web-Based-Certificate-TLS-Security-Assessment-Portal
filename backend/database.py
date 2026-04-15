from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from config import settings

# ── PostgreSQL / Neon engine (ALL data — auth + scans) ────────────────────────
# NullPool: no persistent connections — essential for serverless (Neon) to avoid
# "connection is closed" errors after the pool idles.
pg_engine = create_async_engine(
    settings.POSTGRES_URL,
    echo=False,
    poolclass=NullPool,
)

pg_session = async_sessionmaker(pg_engine, class_=AsyncSession, expire_on_commit=False)

# Legacy SQLite engine kept for backward compatibility (no longer used for new tables)
engine = pg_engine
async_session = pg_session


class Base(DeclarativeBase):
    """Legacy base — aliased to PGBase so old imports still resolve."""
    pass


class PGBase(DeclarativeBase):
    """Base for ALL models — stored in PostgreSQL (Neon)."""
    pass


async def get_db() -> AsyncSession:
    """Dependency: PostgreSQL session (legacy name kept for backward compat)."""
    async with pg_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# Alias so scan router can use get_pg_db same as auth router
get_pg_db = get_db


async def init_db():
    """Create all PostgreSQL tables (legacy name kept for main.py)."""
    async with pg_engine.begin() as conn:
        await conn.run_sync(PGBase.metadata.create_all)


async def init_pg_db():
    """Create all PostgreSQL (Neon) tables on startup."""
    async with pg_engine.begin() as conn:
        await conn.run_sync(PGBase.metadata.create_all)
