"""Async SQLAlchemy database models and session factory."""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, JSON
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, relationship

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://ssl_monitor:ssl_monitor@localhost:5432/ssl_monitor",
)

_engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
_factory = async_sessionmaker(_engine, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with _factory() as session:
        yield session


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    folders = relationship("Folder", back_populates="user", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")


class Folder(Base):
    __tablename__ = "folders"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="folders")
    scans = relationship("Scan", back_populates="folder")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    folder_id = Column(
        String(36), ForeignKey("folders.id", ondelete="SET NULL"), nullable=True
    )
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    domains_checked = Column(Integer, nullable=False)
    summary = Column(JSON, nullable=False)   # {OK: n, WARNING: n, ...}
    results = Column(JSON, nullable=False)   # serialised CertificateResult list

    user = relationship("User", back_populates="scans")
    folder = relationship("Folder", back_populates="scans", lazy="selectin")


async def init_db() -> None:
    """Create all tables (idempotent — safe to call on every startup)."""
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
