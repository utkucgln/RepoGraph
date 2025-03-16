"""
Concurrency utilities for repository analyzer.

This module provides functions and classes for parallel processing
and concurrent execution of tasks.
"""

import logging
import time
import concurrent.futures
from typing import List, Callable, TypeVar, Any, Dict, Tuple, Optional
from functools import partial

logger = logging.getLogger("utils.concurrency")

T = TypeVar('T')
R = TypeVar('R')


def parallel_map(func: Callable[[T], R],
                 items: List[T],
                 max_workers: int = 10,
                 timeout: Optional[float] = None,
                 use_processes: bool = False,
                 chunk_size: int = 1) -> List[R]:
    """Execute a function on items in parallel.

    Args:
        func: Function to execute on each item
        items: List of items to process
        max_workers: Maximum number of parallel workers
        timeout: Maximum time to wait for completion (None for no limit)
        use_processes: Whether to use processes instead of threads
        chunk_size: Number of items to process in each worker

    Returns:
        List of results in the same order as the input items
    """
    if not items:
        return []

    # Determine executor type
    executor_class = concurrent.futures.ProcessPoolExecutor if use_processes else concurrent.futures.ThreadPoolExecutor

    # Adjust max_workers based on item count
    effective_workers = min(max_workers, (len(items) + chunk_size - 1) // chunk_size)

    logger.debug(
        f"Running {len(items)} items with {effective_workers} workers (using {'processes' if use_processes else 'threads'})")

    results = []
    with executor_class(max_workers=effective_workers) as executor:
        # Create chunked items if needed
        if chunk_size > 1:
            chunked_items = [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]
            chunked_results = list(
                executor.map(lambda chunk: [func(item) for item in chunk], chunked_items, timeout=timeout))
            # Flatten results
            for chunk in chunked_results:
                results.extend(chunk)
        else:
            # Process items individually
            results = list(executor.map(func, items, timeout=timeout))

    return results


def parallel_process_with_progress(func: Callable[[T], R],
                                   items: List[T],
                                   max_workers: int = 10,
                                   update_interval: float = 1.0,
                                   desc: str = "Processing",
                                   use_processes: bool = False) -> List[R]:
    """Execute a function on items in parallel with progress reporting.

    Args:
        func: Function to execute on each item
        items: List of items to process
        max_workers: Maximum number of parallel workers
        update_interval: How often to log progress (in seconds)
        desc: Description for the progress reporting
        use_processes: Whether to use processes instead of threads

    Returns:
        List of results in the same order as the input items
    """
    from src.utils.logging_utils import StatusLogger

    if not items:
        return []

    # Set up status reporting
    status = StatusLogger(len(items), desc)
    completed = 0
    results = [None] * len(items)
    errors = []

    # Function to track completion
    def process_item_with_tracking(idx, item):
        nonlocal completed
        try:
            result = func(item)
            return idx, result, None
        except Exception as e:
            return idx, None, str(e)

    # Determine executor type
    executor_class = concurrent.futures.ProcessPoolExecutor if use_processes else concurrent.futures.ThreadPoolExecutor

    with executor_class(max_workers=max_workers) as executor:
        # Submit all tasks
        futures = [executor.submit(process_item_with_tracking, i, item)
                   for i, item in enumerate(items)]

        # Process results as they complete
        last_update_time = time.time()
        for future in concurrent.futures.as_completed(futures):
            idx, result, error = future.result()
            results[idx] = result
            completed += 1

            if error:
                errors.append((idx, error))
                logger.warning(f"Error processing item {idx}: {error}")

            # Update progress periodically
            current_time = time.time()
            if current_time - last_update_time >= update_interval:
                status.update(completed)
                last_update_time = current_time

    status.complete(f"Completed with {len(errors)} errors")

    if errors:
        logger.warning(f"Encountered {len(errors)} errors during processing")

    return results


def retry(func: Callable,
          max_retries: int = 3,
          retry_delay: float = 1.0,
          backoff_factor: float = 2.0,
          exceptions: Tuple = (Exception,)) -> Any:
    """Retry a function multiple times with exponential backoff.

    Args:
        func: Function to retry
        max_retries: Maximum number of retry attempts
        retry_delay: Initial delay between retries in seconds
        backoff_factor: Factor to increase delay by after each retry
        exceptions: Tuple of exceptions to catch and retry on

    Returns:
        Result of the function call

    Raises:
        Exception: The last exception if all retries fail
    """
    last_exception = None

    for attempt in range(max_retries + 1):  # +1 for the initial attempt
        try:
            return func()
        except exceptions as e:
            last_exception = e

            if attempt < max_retries:
                delay = retry_delay * (backoff_factor ** attempt)
                logger.warning(f"Attempt {attempt + 1}/{max_retries + 1} failed: {str(e)}. Retrying in {delay:.2f}s...")
                time.sleep(delay)
            else:
                # Last attempt failed
                logger.error(f"All {max_retries + 1} attempts failed. Last error: {str(e)}")

    # If we get here, all retries failed
    raise last_exception


def rate_limited(func: Callable,
                 rate_limit: float) -> Callable:
    """Create a rate-limited version of a function.

    Args:
        func: Function to rate limit
        rate_limit: Maximum calls per second

    Returns:
        Rate-limited function
    """
    min_interval = 1.0 / rate_limit
    last_call_time = [0.0]  # Use a list for mutable state in closure

    def rate_limited_func(*args, **kwargs):
        current_time = time.time()
        elapsed = current_time - last_call_time[0]

        # If we need to wait to respect the rate limit
        if elapsed < min_interval:
            sleep_time = min_interval - elapsed
            time.sleep(sleep_time)

        # Execute the function
        result = func(*args, **kwargs)

        # Update the last call time
        last_call_time[0] = time.time()
        return result

    return rate_limited_func


class RateLimitedExecutor:
    """Executor for running tasks with rate limiting.

    This class provides a way to execute tasks with a maximum
    rate of requests per second.
    """

    def __init__(self, max_workers: int = 10,
                 rate_limit: Optional[float] = None,
                 use_processes: bool = False):
        """Initialize the rate-limited executor.

        Args:
            max_workers: Maximum number of parallel workers
            rate_limit: Maximum requests per second (None for no limit)
            use_processes: Whether to use processes instead of threads
        """
        self.max_workers = max_workers
        self.rate_limit = rate_limit
        self.use_processes = use_processes

        # Initialize executor based on type
        executor_class = concurrent.futures.ProcessPoolExecutor if use_processes else concurrent.futures.ThreadPoolExecutor
        self.executor = executor_class(max_workers=max_workers)

        # For tracking request timing
        self.last_request_time = 0.0
        self.min_interval = 1.0 / rate_limit if rate_limit else 0.0

    def submit(self, func: Callable, *args, **kwargs) -> concurrent.futures.Future:
        """Submit a task for execution.

        Args:
            func: Function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function

        Returns:
            Future representing the execution of the task
        """
        # Apply rate limiting if needed
        if self.rate_limit:
            current_time = time.time()
            elapsed = current_time - self.last_request_time

            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                time.sleep(sleep_time)

            self.last_request_time = time.time()

        # Submit the task
        return self.executor.submit(func, *args, **kwargs)

    def map(self, func: Callable[[T], R], items: List[T]) -> List[R]:
        """Apply a function to each item in a collection.

        Args:
            func: Function to apply
            items: Collection of items to process

        Returns:
            List of results
        """
        # If rate limiting is enabled, wrap the function
        if self.rate_limit:
            map_func = rate_limited(func, self.rate_limit)
        else:
            map_func = func

        return list(self.executor.map(map_func, items))

    def shutdown(self, wait: bool = True) -> None:
        """Shut down the executor.

        Args:
            wait: Whether to wait for pending tasks to complete
        """
        self.executor.shutdown(wait=wait)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()