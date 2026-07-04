"""DuckDB database manager for EAIP."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

import duckdb
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

import structlog

if TYPE_CHECKING:
    from sqlalchemy import Engine
    from config.settings import EAIPSettings

from src.storage.schema import Base

logger = structlog.get_logger(__name__)


class DatabaseManager:
    """Manages DuckDB database connections and operations.

    Provides both SQLAlchemy ORM access and direct DuckDB access
    for operations like Parquet import/export.

    Args:
        db_path: Path to the DuckDB database file, or ':memory:' for in-memory.
    """

    def __init__(self, db_path: str = "./data/eaip.duckdb") -> None:
        self.db_path = db_path
        self._engine: Engine | None = None
        self._session_factory: sessionmaker | None = None

        # Create data directory if using file-based DB
        if db_path != ":memory:":
            db_dir = os.path.dirname(db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)

        logger.info("database_init", path=db_path)

    def get_engine(self) -> Engine:
        """Get or create the SQLAlchemy engine.

        Returns:
            SQLAlchemy Engine connected to DuckDB.
        """
        if self._engine is None:
            if self.db_path == ":memory:":
                uri = "duckdb:///:memory:"
            else:
                uri = f"duckdb:///{self.db_path}"
            self._engine = create_engine(uri)
            logger.debug("engine_created", uri=uri)
        return self._engine

    def get_session(self) -> Session:
        """Create a new database session.

        Returns:
            A new SQLAlchemy Session.
        """
        if self._session_factory is None:
            self._session_factory = sessionmaker(bind=self.get_engine())
        return self._session_factory()

    def get_connection(self) -> duckdb.DuckDBPyConnection:
        """Get a raw DuckDB connection for direct operations.

        Returns:
            A DuckDB connection for COPY, READ_PARQUET, etc.
        """
        return duckdb.connect(self.db_path)

    def initialize_schema(self) -> None:
        """Create all tables defined in the ORM schema."""
        engine = self.get_engine()
        Base.metadata.create_all(engine)
        logger.info("schema_initialized", tables=len(Base.metadata.tables))

    def export_to_parquet(self, table_name: str, output_path: str) -> None:
        """Export a table to a Parquet file using DuckDB COPY.

        Args:
            table_name: Name of the table to export.
            output_path: Path for the output Parquet file.
        """
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        conn = self.get_connection()
        try:
            conn.execute(f"COPY {table_name} TO '{output_path}' (FORMAT PARQUET, COMPRESSION ZSTD)")
            logger.info("exported_to_parquet", table=table_name, path=output_path)
        finally:
            conn.close()

    def import_from_parquet(self, table_name: str, parquet_path: str) -> None:
        """Import data from a Parquet file into a table.

        Args:
            table_name: Target table name.
            parquet_path: Path to the Parquet file.
        """
        conn = self.get_connection()
        try:
            conn.execute(f"COPY {table_name} FROM '{parquet_path}' (FORMAT PARQUET)")
            logger.info("imported_from_parquet", table=table_name, path=parquet_path)
        finally:
            conn.close()

    def execute_sql_file(self, file_path: str) -> None:
        """Read and execute a SQL file.

        Args:
            file_path: Path to the .sql file.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"SQL file not found: {file_path}")

        sql_content = path.read_text(encoding="utf-8")
        # Split on semicolons and execute each statement
        statements = [s.strip() for s in sql_content.split(";") if s.strip()]

        conn = self.get_connection()
        try:
            for stmt in statements:
                if stmt and not stmt.startswith("--"):
                    conn.execute(stmt)
            logger.info("sql_file_executed", path=file_path, statements=len(statements))
        finally:
            conn.close()

    def __enter__(self) -> DatabaseManager:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._engine:
            self._engine.dispose()
            self._engine = None
            self._session_factory = None


@lru_cache(maxsize=1)
def get_database(db_path: str = "./data/eaip.duckdb") -> DatabaseManager:
    """Get a cached DatabaseManager instance.

    Args:
        db_path: Path to the DuckDB file.

    Returns:
        Singleton DatabaseManager.
    """
    return DatabaseManager(db_path=db_path)
