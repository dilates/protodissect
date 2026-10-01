"""Message type clustering (pipeline-spec 3, ADR-0006).

Group messages whose fields align: for length-prefixed framing, the constant prefix
(magic + type) is the cluster key since payload length legitimately varies within a
type; otherwise exact length buckets merged when byte-value histograms are
simhash-similar (>= 0.9). Deterministic by construction.
"""

from __future__ import annotations

import hashlib
from collections import Counter

from .models import Message

PREFIX_BYTES = 4
SIMHASH_MERGE_THRESHOLD = 0.9


def simhash64(tokens: list[str]) -> int:
    counts = Counter(tokens)
    v = [0] * 64
    for token, weight in counts.items():
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        h = int.from_bytes(digest, "big")
        for i in range(64):
            v[i] += weight if (h >> i) & 1 else -weight
    out = 0
    for i in range(64):
        if v[i] > 0:
            out |= 1 << i
    return out


def simhash_similarity(a: int, b: int) -> float:
    return 1.0 - (a ^ b).bit_count() / 64.0


def _byte_tokens(data: bytes) -> list[str]:
    return [f"{b:02x}" for b in data]


def cluster_messages(messages: list[Message], framing: str = "unknown") -> list[list[Message]]:
    """Cluster messages per direction; deterministic (stable sort everywhere)."""
    if framing == "length_prefixed":
        return _cluster_by_prefix(messages)
    return _cluster_by_length(messages)


def _cluster_by_prefix(messages: list[Message]) -> list[list[Message]]:
    buckets: dict[tuple[str, bytes], list[Message]] = {}
    for msg in messages:
        buckets.setdefault((msg.dir, msg.data[:PREFIX_BYTES]), []).append(msg)
    clusters: list[list[Message]] = [
        buckets[key] for key in sorted(buckets, key=lambda k: (k[0], k[1]))
    ]
    for cluster in clusters:
        cluster.sort(key=lambda m: m.ts)
    return clusters


def _cluster_by_length(messages: list[Message]) -> list[list[Message]]:
    buckets: dict[tuple[str, int], list[Message]] = {}
    for msg in messages:
        buckets.setdefault((msg.dir, len(msg.data)), []).append(msg)

    clusters: list[list[Message]] = []
    for key in sorted(buckets, key=lambda k: (k[0], k[1])):
        bucket = buckets[key]
        merged = False
        for cluster in clusters:
            if cluster[0].dir != key[0]:
                continue
            same_len = len(cluster[0].data) == len(bucket[0].data)
            if same_len:
                cluster.extend(bucket)
                merged = True
                break
            sim = simhash_similarity(
                simhash64(_byte_tokens(cluster[0].data)), simhash64(_byte_tokens(bucket[0].data))
            )
            if sim >= SIMHASH_MERGE_THRESHOLD:
                cluster.extend(bucket)
                merged = True
                break
        if not merged:
            clusters.append(list(bucket))
    for cluster in clusters:
        cluster.sort(key=lambda m: m.ts)
    return clusters
