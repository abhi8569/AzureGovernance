"""Generic async paginators for Microsoft APIs."""
from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

import httpx
import structlog

from src.utils.retry import handle_retry_after

logger = structlog.get_logger(__name__)


async def paginate_graph(
    client: httpx.AsyncClient,
    url: str,
    headers: dict[str, str],
    params: dict[str, Any] | None = None,
    max_pages: int | None = None,
) -> AsyncGenerator[list[dict[str, Any]], None]:
    """Paginate Microsoft Graph API responses.

    Follows @odata.nextLink for pagination.

    Args:
        client: HTTPX async client.
        url: Initial request URL.
        headers: Request headers with auth.
        params: Optional query parameters.
        max_pages: Maximum pages to fetch (None = unlimited).

    Yields:
        Lists of items from each page.
    """
    current_url = url
    page_count = 0

    while current_url:
        if max_pages and page_count >= max_pages:
            logger.info("pagination_max_reached", pages=page_count)
            break

        response = await client.get(current_url, headers=headers, params=params if page_count == 0 else None)
        handle_retry_after(response)
        response.raise_for_status()

        data = response.json()
        items = data.get("value", [])

        if items:
            yield items

        page_count += 1
        current_url = data.get("@odata.nextLink")
        logger.debug("page_fetched", page=page_count, items=len(items), has_next=bool(current_url))


async def paginate_rest(
    client: httpx.AsyncClient,
    url: str,
    headers: dict[str, str],
    params: dict[str, Any] | None = None,
    next_link_key: str = "nextLink",
    value_key: str = "value",
    max_pages: int | None = None,
) -> AsyncGenerator[list[dict[str, Any]], None]:
    """Paginate generic REST API responses.

    Args:
        client: HTTPX async client.
        url: Initial request URL.
        headers: Request headers.
        params: Optional query parameters.
        next_link_key: JSON key for the next page URL.
        value_key: JSON key for the items array.
        max_pages: Maximum pages to fetch.

    Yields:
        Lists of items from each page.
    """
    current_url = url
    page_count = 0

    while current_url:
        if max_pages and page_count >= max_pages:
            break

        response = await client.get(current_url, headers=headers, params=params if page_count == 0 else None)
        handle_retry_after(response)
        response.raise_for_status()

        data = response.json()
        items = data.get(value_key, [])

        if items:
            yield items

        page_count += 1
        current_url = data.get(next_link_key)
        logger.debug("rest_page_fetched", page=page_count, items=len(items))


async def paginate_fabric(
    client: httpx.AsyncClient,
    url: str,
    headers: dict[str, str],
    max_pages: int | None = None,
) -> AsyncGenerator[list[dict[str, Any]], None]:
    """Paginate Fabric REST API responses.

    Fabric uses continuationToken in the response body.

    Args:
        client: HTTPX async client.
        url: Initial request URL.
        headers: Request headers.
        max_pages: Maximum pages to fetch.

    Yields:
        Lists of items from each page.
    """
    current_url = url
    page_count = 0

    while current_url:
        if max_pages and page_count >= max_pages:
            break

        response = await client.get(current_url, headers=headers)
        handle_retry_after(response)
        response.raise_for_status()

        data = response.json()
        items = data.get("value", [])

        if items:
            yield items

        page_count += 1
        continuation_token = data.get("continuationToken")
        if continuation_token:
            separator = "&" if "?" in url else "?"
            current_url = f"{url}{separator}continuationToken={continuation_token}"
        else:
            current_url = None

        logger.debug("fabric_page_fetched", page=page_count, items=len(items))
