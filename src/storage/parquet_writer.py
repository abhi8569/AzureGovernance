"""Parquet file writer with Hive-style partitioning."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pandas as pd
import pyarrow as pa
import pyarrow.dataset as ds
import pyarrow.parquet as pq
import structlog

logger = structlog.get_logger(__name__)


class ParquetWriter:
    """Write and read Parquet files with Hive-style partitioning.

    Files are organized as:
        {output_dir}/{table_name}/tenant={tenant_id}/snapshot_date={date}/data.parquet

    Args:
        output_dir: Base directory for Parquet output.
    """

    def __init__(self, output_dir: str = "./data/parquet") -> None:
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def write_table(
        self,
        data: list[dict[str, Any]],
        table_name: str,
        snapshot_date: str,
        tenant_id: str,
    ) -> str:
        """Write a list of dicts to a partitioned Parquet file.

        Args:
            data: List of record dicts.
            table_name: Logical table name.
            snapshot_date: Snapshot date string (YYYY-MM-DD).
            tenant_id: Tenant identifier.

        Returns:
            Path to the written Parquet file.
        """
        if not data:
            logger.warning("parquet_write_empty", table=table_name)
            return ""

        output_path = self._get_partition_path(table_name, tenant_id, snapshot_date)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        table = pa.Table.from_pylist(data)
        pq.write_table(table, output_path, compression="zstd")

        logger.info("parquet_written", table=table_name, rows=len(data), path=output_path)
        return output_path

    def write_dataframe(
        self,
        df: pd.DataFrame,
        table_name: str,
        snapshot_date: str,
        tenant_id: str,
    ) -> str:
        """Write a pandas DataFrame to a partitioned Parquet file.

        Args:
            df: Pandas DataFrame to write.
            table_name: Logical table name.
            snapshot_date: Snapshot date string (YYYY-MM-DD).
            tenant_id: Tenant identifier.

        Returns:
            Path to the written Parquet file.
        """
        if df.empty:
            logger.warning("parquet_write_empty_df", table=table_name)
            return ""

        output_path = self._get_partition_path(table_name, tenant_id, snapshot_date)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        table = pa.Table.from_pandas(df)
        pq.write_table(table, output_path, compression="zstd")

        logger.info("parquet_written", table=table_name, rows=len(df), path=output_path)
        return output_path

    def read_table(
        self,
        table_name: str,
        tenant_id: str | None = None,
        snapshot_date: str | None = None,
    ) -> pa.Table:
        """Read Parquet data for a table with optional partition filters.

        Args:
            table_name: Logical table name.
            tenant_id: Optional tenant filter.
            snapshot_date: Optional snapshot date filter.

        Returns:
            PyArrow Table with the data.
        """
        table_dir = os.path.join(self.output_dir, table_name)
        if not os.path.exists(table_dir):
            logger.warning("parquet_read_not_found", table=table_name)
            return pa.table({})

        dataset = ds.dataset(table_dir, format="parquet", partitioning="hive")

        filters = []
        if tenant_id:
            filters.append(ds.field("tenant") == tenant_id)
        if snapshot_date:
            filters.append(ds.field("snapshot_date") == snapshot_date)

        combined_filter = None
        for f in filters:
            combined_filter = f if combined_filter is None else (combined_filter & f)

        result = dataset.to_table(filter=combined_filter) if combined_filter else dataset.to_table()
        logger.info("parquet_read", table=table_name, rows=result.num_rows)
        return result

    def list_snapshots(self, table_name: str) -> list[str]:
        """List available snapshot dates for a table.

        Args:
            table_name: Logical table name.

        Returns:
            Sorted list of snapshot date strings.
        """
        table_dir = Path(self.output_dir) / table_name
        if not table_dir.exists():
            return []

        snapshots = set()
        for path in table_dir.rglob("*.parquet"):
            for part in path.parts:
                if part.startswith("snapshot_date="):
                    snapshots.add(part.split("=", 1)[1])

        return sorted(snapshots)

    def _get_partition_path(
        self, table_name: str, tenant_id: str, snapshot_date: str
    ) -> str:
        """Build the Hive-partitioned file path."""
        return os.path.join(
            self.output_dir,
            table_name,
            f"tenant={tenant_id}",
            f"snapshot_date={snapshot_date}",
            "data.parquet",
        )
