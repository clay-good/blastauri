"""Async HTTP client with rate limiting and retries."""

import asyncio
import time
from typing import Any

import httpx

from blastauri.utils.logging import get_logger

logger = get_logger(__name__)


class RateLimiter:
    """Token bucket rate limiter for API requests.

    Implements a simple token bucket algorithm to limit request rates.
    """

    def __init__(
        self,
        requests_per_window: int,
        window_seconds: float,
    ) -> None:
        """Initialize the rate limiter.

        Args:
            requests_per_window: Maximum requests allowed per window.
            window_seconds: Time window in seconds.
        """
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.tokens = float(requests_per_window)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary.

        Blocks until a token is available.
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now

            self.tokens += elapsed * (self.requests_per_window / self.window_seconds)
            if self.tokens > self.requests_per_window:
                self.tokens = float(self.requests_per_window)

            if self.tokens < 1:
                wait_time = (1 - self.tokens) * (
                    self.window_seconds / self.requests_per_window
                )
                logger.debug("Rate limit: waiting %.2f seconds", wait_time)
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class AsyncHttpClient:
    """Async HTTP client with retry and rate limiting support.

    Features:
    - Configurable timeout
    - Exponential backoff retries
    - Rate limiting
    - Automatic JSON parsing
    """

    DEFAULT_TIMEOUT = 30.0
    DEFAULT_RETRIES = 3
    RETRY_DELAYS = [1.0, 2.0, 4.0]

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_RETRIES,
        rate_limiter: RateLimiter | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Initialize the HTTP client.

        Args:
            base_url: Base URL for requests.
            timeout: Request timeout in seconds.
            max_retries: Maximum number of retries.
            rate_limiter: Optional rate limiter instance.
            headers: Default headers for all requests.
        """
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.rate_limiter = rate_limiter
        self.default_headers = headers or {}
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "AsyncHttpClient":
        """Enter async context."""
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers=self.default_headers,
            follow_redirects=True,
        )
        return self

    async def __aexit__(
        self,
        exc_type: type | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Exit async context."""
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        """Get the underlying httpx client."""
        if self._client is None:
            raise RuntimeError("Client not initialized. Use async with statement.")
        return self._client

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Make an HTTP request with retry logic.

        Args:
            method: HTTP method.
            url: Request URL.
            **kwargs: Additional arguments for httpx.

        Returns:
            HTTP response.

        Raises:
            httpx.HTTPError: If all retries fail.
        """
        last_exception: Exception | None = None

        for attempt in range(self.max_retries + 1):
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()

                response = await self.client.request(method, url, **kwargs)

                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After")
                    if retry_after:
                        wait_time = float(retry_after)
                    else:
                        wait_time = self.RETRY_DELAYS[min(attempt, len(self.RETRY_DELAYS) - 1)]
                    logger.warning(
                        "Rate limited (429), waiting %.1f seconds", wait_time
                    )
                    await asyncio.sleep(wait_time)
                    continue

                response.raise_for_status()
                return response

            except httpx.HTTPStatusError as e:
                if e.response.status_code >= 500:
                    last_exception = e
                    if attempt < self.max_retries:
                        delay = self.RETRY_DELAYS[min(attempt, len(self.RETRY_DELAYS) - 1)]
                        logger.warning(
                            "Server error %d, retrying in %.1f seconds",
                            e.response.status_code,
                            delay,
                        )
                        await asyncio.sleep(delay)
                        continue
                raise

            except (httpx.ConnectError, httpx.ReadTimeout) as e:
                last_exception = e
                if attempt < self.max_retries:
                    delay = self.RETRY_DELAYS[min(attempt, len(self.RETRY_DELAYS) - 1)]
                    logger.warning(
                        "Connection error, retrying in %.1f seconds: %s",
                        delay,
                        str(e),
                    )
                    await asyncio.sleep(delay)
                    continue
                raise

        if last_exception:
            raise last_exception
        raise RuntimeError("Unexpected retry loop exit")

    async def get(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Make a GET request.

        Args:
            url: Request URL.
            params: Query parameters.
            headers: Additional headers.

        Returns:
            HTTP response.
        """
        return await self._request("GET", url, params=params, headers=headers)

    async def post(
        self,
        url: str,
        json: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Make a POST request.

        Args:
            url: Request URL.
            json: JSON body.
            data: Form data.
            headers: Additional headers.

        Returns:
            HTTP response.
        """
        return await self._request("POST", url, json=json, data=data, headers=headers)

    async def get_json(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Make a GET request and parse JSON response.

        Args:
            url: Request URL.
            params: Query parameters.
            headers: Additional headers.

        Returns:
            Parsed JSON data.
        """
        response = await self.get(url, params=params, headers=headers)
        return response.json()

    async def post_json(
        self,
        url: str,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Make a POST request and parse JSON response.

        Args:
            url: Request URL.
            json: JSON body.
            headers: Additional headers.

        Returns:
            Parsed JSON data.
        """
        response = await self.post(url, json=json, headers=headers)
        return response.json()


def create_nvd_rate_limiter(has_api_key: bool = False) -> RateLimiter:
    """Create a rate limiter configured for NVD API.

    Args:
        has_api_key: Whether an NVD API key is available.

    Returns:
        Configured rate limiter.
    """
    if has_api_key:
        return RateLimiter(requests_per_window=50, window_seconds=30)
    return RateLimiter(requests_per_window=5, window_seconds=30)
