from __future__ import annotations

from typing import Generic, TypeVar

V = TypeVar("V")


class FifoCache(Generic[V]):
    """
    Simple fixed-size FIFO cache.
    Evicts oldest 10% of entries when capacity is reached.
    """

    def __init__(self, maxsize: int = 5_000) -> None:
        self._maxsize = maxsize
        self._store: dict[str, V] = {}

    def get(self, key: str) -> V | None:
        return self._store.get(key)

    def set(self, key: str, value: V) -> None:
        self._evict_if_full()
        self._store[key] = value

    def __contains__(self, key: str) -> bool:
        return key in self._store

    def __len__(self) -> int:
        return len(self._store)

    def _evict_if_full(self) -> None:
        if len(self._store) >= self._maxsize:
            evict_count = max(1, self._maxsize // 10)
            for key in list(self._store.keys())[:evict_count]:
                del self._store[key]
