"""Core primitives for selective Hindsight memory and nightly skill review.

This module intentionally has no Nanobot dependency.  The Nanobot adapter lives
in ``nanobot_hindsight.py`` so the retention policy, ledger, and HTTP client can
be tested without starting an agent.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence


SCHEMA_VERSION = 5
MIN_HINDSIGHT_VERSION = (0, 8, 6)
NIGHTLY_MARKER = "[NANOBOT_HINDSIGHT_NIGHTLY]"
SEEN_EVIDENCE_RETENTION_DAYS = 35

ALLOWED_CATEGORIES = frozenset(
    {
        "preference",
        "constraint",
        "person",
        "project",
        "durable_fact",
        "decision",
        "commitment",
        "event",
        "open_issue",
        "resolved_error",
    }
)
MUTABLE_CATEGORIES = frozenset(
    {"preference", "constraint", "person", "project", "durable_fact", "open_issue"}
)
ALLOWED_FINDING_KINDS = frozenset(
    {
        "existing_skill_failure",
        "missing_skill_opportunity",
        "routing_gap",
        "dependency_incident",
        "observation_gap",
        "skill_success",
    }
)

_SECRET_PATTERNS = (
    re.compile(
        r"(?is)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
        r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    ),
    re.compile(
        r"(?im)\b(?:api[_ -]?key|hindsight[_ -]?key|credential|secret|password|"
        r"passwd|pwd|passcode|passphrase|pin(?:\s+(?:code|number))?|"
        r"token|access[_ -]?token|otp|"
        r"(?:2fa|mfa|totp|authenticator)[_ -]?(?:code|secret|token)|"
        r"backup[_ -]?code|login[_ -]?code|one[_ -]?time[_ -]?code|"
        r"recovery[_ -]?(?:code|key)|verification[_ -]?code|seed\s+phrase|"
        r"recovery\s+phrase|mnemonic\s+phrase)\b"
        r"(?:\s+for\s+(?:[A-Za-z0-9._-]{1,40}\s+){0,3}"
        r"[A-Za-z0-9._-]{1,40})?\s*[\"']?\s*"
        r"(?:[:=]|['’]s\b|\bis\b|\bwas\b|\bwill\s+be\b)\s*[^\r\n]+"
    ),
    re.compile(
        r"(?i)\b(?:api[_ -]?key|hindsight[_ -]?key|credential|secret|password|"
        r"passwd|pwd|passcode|passphrase|token|access[_ -]?token)\b\s+"
        r"(?=[A-Za-z0-9_+/=-]{4,}\b)(?=[A-Za-z0-9_+/=-]*[0-9_+/=-])"
        r"[A-Za-z0-9_+/=-]{4,}\b[^\r\n]*"
    ),
    re.compile(
        r"(?i)\b(?:backup|login|one[- ]time|recovery|verification|2fa|mfa|"
        r"totp|authenticator)\s+codes?\b"
        r"\s*(?:(?:[:=]|['’]s\b|\bis\b|\bwas\b)\s*)?"
        r"[A-Za-z0-9][A-Za-z0-9-]{3,}\b"
    ),
    re.compile(
        r"(?i)\b(?:2fa|mfa|totp|authenticator)\b\s*"
        r"(?:[:=]|['’]s\b|\bis\b|\bwas\b)\s*"
        r"(?:\d{4,12}|[A-Z2-7]{12,})\b"
    ),
    re.compile(
        r"(?i)\botp\b\s*(?:(?:[:=]|\bis\b|\bwas\b)\s*)?"
        r"[A-Za-z0-9][A-Za-z0-9-]{3,}\b"
    ),
    re.compile(r"(?i)\bpin(?:\s+(?:code|number))?\b\s+\d{4,12}\b[^\r\n]*"),
    re.compile(
        r"(?i)\b(?:(?:cvv|cvc|security\s+code)\b\s*"
        r"(?:(?:[:=]|\bis\b|\bwas\b)\s*)?\d{3,4}\b|"
        r"card\s+(?:expiry|expiration)\b\s*"
        r"(?:(?:[:=]|\bis\b|\bwas\b)\s*)?\d{1,2}/\d{2,4}\b)"
        r"[^.!?\r\n]*(?:[.!?]|$)"
    ),
    re.compile(
        r"(?i)\b(?:my\s+)?(?:private\s+key|security\s+answer|"
        r"mother['’]?s\s+maiden\s+name|(?:auth|authentication|session)\s+cookie)\b"
        r"\s*(?:[:=]|\bis\b|\bwas\b|\bwill\s+be\b)\s*"
        r"[^.!?\r\n]+(?:[.!?]|$)"
    ),
    re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+\S+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bgh[opusr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bAIza[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}\b"),
    re.compile(r"\b(?:hsk|hs|hindsight)_[A-Za-z0-9_-]{12,}\b", re.I),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)\bhttps?://[^\s/:]+:[^\s/@]+@[^\s]+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(
        r"(?i)\b(?:ssn|social\s+security(?:\s+number)?|national\s+id|tax\s+id|"
        r"passport(?:\s+number)?|driver.?s\s+licen[cs]e|credit\s+card|debit\s+card|"
        r"bank\s+account(?!\s+(?:field|form|parser|screen|validation)\b)|"
        r"routing\s+number|iban)\b[^.!?\r\n]*(?:[.!?]|$)"
    ),
    re.compile(
        r"(?i)\b(?:account\s+balance|bankruptcy|credit\s+(?:report|score)|debt|"
        r"financial\s+(?:account|condition|information|status)|income|investments?|"
        r"brokerage|checking\s+account|savings\s+account|stocks?|shares?|"
        r"loan\s+balance|mortgage|net\s+worth|retirement\s+account|"
        r"salary(?!\s+(?:calculator|field|parser|validation)\b)|tax\s+return|"
        r"wages?|compensation)"
        r"\b[^.!?\r\n]*(?:[.!?]|$)"
    ),
    re.compile(
        r"(?i)(?:\$\s*\d[\d,]*(?:\.\d{1,2})?|"
        r"\b(?:buy|sell|own|hold|invest(?:\s+in)?)\b[^.!?\r\n]{0,60}"
        r"\b(?:bitcoin|btc|ethereum|eth|crypto|stock|shares?)\b)"
        r"[^.!?\r\n]*(?:[.!?]|$)"
    ),
    re.compile(
        r"(?i)\b(?:religion|religious\s+belief|faith|political\s+affiliation|"
        r"political\s+party|sexual\s+orientation|gender\s+identity|"
        r"race(?!\s+condition\b)|ethnicity|"
        r"agnostic|atheist|buddhist|catholic|christian|hindu|islam|jewish|judaism|"
        r"muslim|church|mosque|synagogue|(?:catholic\s+)?mass|vote|"
        r"voting(?!\s+(?:app|code|feature|logic|module|system)\b)|ballot|"
        r"election|trump|biden|harris|maga|democrat(?:ic)?|republican|libertarian|"
        r"bisexual|gay|heterosexual|homosexual|"
        r"lesbian|nonbinary|queer|transgender|trade\s+union|union\s+membership|"
        r"biometric)"
        r"\b[^.!?\r\n]*(?:[.!?]|$)"
    ),
    re.compile(
        r"(?i)\b(?:support|join|member\s+of|vote\s+for)\b[^.!?\r\n]{0,60}"
        r"\b(?:party|union)\b[^.!?\r\n]*(?:[.!?]|$)|"
        r"\b(?:become|identify\s+as|am)\s+(?:a\s+)?"
        r"(?:socialist|communist|conservative|liberal)\b[^.!?\r\n]*(?:[.!?]|$)"
    ),
    re.compile(
        r"(?i)\bi\s+(?:am|identify\s+as)\s+(?:black|white|asian|hispanic|"
        r"latino|latina|african\s+american|native\s+american)\b"
        r"[^.!?\r\n]*(?:[.!?]|$)"
    ),
    re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
    re.compile(
        r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}(?!\d)"
    ),
    re.compile(
        r"(?i)\b(?:card(?:\s+number)?|visa|mastercard|master\s+card|amex|"
        r"american\s+express|discover)\b[^\d\r\n]{0,24}(?:\d[ -]?){13,19}\b"
        r"[^.!?\r\n]*(?:[.!?]|$)"
    ),
    re.compile(
        r"(?i)\b(?:(?:my|our)\s+(?:new\s+)?address|"
        r"(?:home|mailing|street)\s+address)\b"
        r"[^.!?\r\n]*(?:[.!?]|$)"
    ),
    re.compile(
        r"(?i)(?<!\w)\d{1,6}\s+[a-z0-9][a-z0-9 .'\-]{0,60}\s+"
        r"(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|"
        r"court|ct|way)\b\.?[^.!?\r\n]*(?:[.!?]|$)"
    ),
)
_HEALTH_DATA_RE = re.compile(
    r"(?i)\b(?:aids|allerg(?:y|ies|ic)|anxiety|arthritis|asthma|autis(?:m|tic)|"
    r"bipolar|blood\s+pressure|cancer|chemotherapy|cholesterol|clinical|covid|"
    r"cardiac|dementia|depression|diabet(?:es|ic)|diagnos(?:is|ed)|dialysis|"
    r"disab(?:ility|led)|disease|doctor|epilepsy|fertility|genetic|health(?:care)?|"
    r"heart\s+disease|hiv|hospital|hypertension|illness|infection|ivf|kidney|"
    r"leukemia|liver|lymphoma|medical|medication|mental\s+health|migraine|"
    r"miscarriage|nurse|parkinson|physician|prescription|pregnan(?:cy|t)|ptsd|"
    r"radiation|radiotherapy|schizophrenia|stroke|surger(?:y|ies)|surgical|syndrome|"
    r"symptoms?|therapy|transplant|treatment|tumou?r|vaccin(?:e|ation)|"
    r"clinician|dentist|surgeon|therapist|psychiatrist|[a-z]{2,}ologist|clinic)"
    r"\b"
)
_KNOWN_MEDICATION_RE = re.compile(
    r"(?i)\b(?:albuterol|amoxicillin|aspirin|atorvastatin|gabapentin|humira|insulin|"
    r"levothyroxine|lisinopril|lithium|metformin|omeprazole|ozempic|penicillin|"
    r"sertraline|warfarin|xarelto|"
    r"[a-z]{4,}(?:cillin|cycline|formin|olol|opram|oxetine|prazole|pril|sartan|"
    r"statin))\b"
)
_KNOWN_CONDITION_PATTERN = (
    r"aids|anxiety|arthritis|asthma|atrial\s+fibrillation|autism|bipolar|cancer|"
    r"copd|covid|crohn(?:'s)?(?:\s+disease)?|depression|diabetes|epilepsy|"
    r"heart\s+disease|hiv|hypertension|hypothyroidism|infection|kidney\s+disease|"
    r"leukemia|lupus|lymphoma|migraine|multiple\s+sclerosis|parkinson(?:'s)?"
    r"(?:\s+disease)?|ptsd|stroke"
)
_KNOWN_CONDITION_RE = re.compile(rf"(?i)\b(?:{_KNOWN_CONDITION_PATTERN})\b")
_HIGH_ENTROPY_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9])[A-Fa-f0-9]{32,}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])"),
    re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{48,}(?![A-Za-z0-9_-])"),
)
_PAN_CANDIDATE_RE = re.compile(
    r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"
)
_SSN_SHAPE_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_IBAN_CANDIDATE_RE = re.compile(
    r"(?i)(?<![A-Z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}(?![A-Z0-9])"
)
_OPAQUE_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{20,}(?![A-Za-z0-9])")
_RAW_ERROR_PATTERNS = (
    re.compile(r"(?i)traceback \(most recent call last\)"),
    re.compile(r"(?i)\bat [\w.$<>]+\([^\n]+:\d+\)"),
    re.compile(r"(?i)\b(?:stderr|stack trace)\s*[:=]"),
)
_TOOL_ERROR_PATTERNS = (
    re.compile(r"(?i)^\s*(?:error|failed|failure)\b"),
    re.compile(r"(?i)\btool error\b"),
    re.compile(r"(?i)\bcommand failed\b"),
    re.compile(r"(?i)\b(?:exception|traceback)\b"),
    re.compile(r'(?i)"is_error"\s*:\s*true'),
)
_TOOL_FAILURE_SUMMARY_PATTERNS = (
    re.compile(r"(?i)\b[1-9]\d*\s+(?:failed|failures?|errors?)\b"),
    re.compile(r"(?i)\b(?:failed|failures?|errors?)\s*[:=]\s*[1-9]\d*\b"),
)
_TOOL_NEGATIVE_SUCCESS_PATTERNS = (
    re.compile(r"(?i)\b(?:0|no)\s+tests?\s+passed\b|\b0\s+passed\b"),
    re.compile(r'(?i)"?success"?\s*[:=]\s*false\b'),
    re.compile(r"(?i)\bcompleted\s+(?:with\s+errors?|unsuccessfully)\b"),
    re.compile(r"(?i)\bdid\s+not\s+pass\b"),
)
_TOOL_CONTEXTUAL_FAILURE_PATTERNS = (
    re.compile(r"(?i)\b(?:assertions?\s+)?(?:failed|failing)\b"),
    re.compile(r"(?i)\btests?\s+passed\s*\?\s*no\b"),
    re.compile(r"(?i)\b(?:run|tests?|checks?)\s+(?:was|were)\s+skipped\b"),
    re.compile(r"(?i)\b(?:tests?|checks?|run)\s+(?:was|were\s+)?not\s+run\b"),
    re.compile(r"(?i)\bpassed\s+(?:previously|in\s+(?:the\s+)?documentation)\b"),
)
_TOOL_SUCCESS_PATTERNS = (
    re.compile(r"(?i)\b\d+ passed\b"),
    re.compile(r"(?i)\btests? passed\b"),
    re.compile(r"(?i)^\s*success\b"),
    re.compile(r"(?i)^\s*completed\s+successfully\b"),
)
_EXIT_STATUS_RE = re.compile(
    r"(?i)\b(?:exit(?:ed)?(?:\s+(?:with\s+)?)?(?:code|status)?|return(?:\s+code)?)"
    r"\s*[:=]?\s*(-?\d+)\b"
)
_SKILL_PATH_RE = re.compile(r"(?P<path>skills[/\\][^\s\"']+?[/\\]SKILL\.md)", re.I)
_QUESTION_RE = re.compile(r"(?i)^\s*(?:who|what|when|where|why|how|can|could|would|should|is|are|do|does)\b")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def observation_order(observed_at: str, candidate_id: str = "") -> tuple[str, str]:
    """Return a comparable UTC timestamp plus deterministic tie breaker."""
    try:
        observed = datetime.fromisoformat(str(observed_at).replace("Z", "+00:00"))
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        stamp = observed.astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError):
        stamp = datetime.min.replace(tzinfo=timezone.utc).isoformat()
    return stamp, clean_text(candidate_id, 128)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def stable_hash(value: Any) -> str:
    raw = value if isinstance(value, str) else canonical_json(value)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def clean_text(value: Any, limit: int = 4_000) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text") or ""))
        text = "\n".join(parts)
    else:
        text = "" if value is None else str(value)
    text = text.replace("\x00", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{4,}", "\n\n\n", text).strip()
    return text[:limit]


def _luhn_valid(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        number = int(character)
        if index % 2 == parity:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def _iban_valid(value: str) -> bool:
    normalized = re.sub(r"\s+", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", normalized):
        return False
    rearranged = normalized[4:] + normalized[:4]
    numeric = "".join(
        str(ord(character) - 55) if character.isalpha() else character
        for character in rearranged
    )
    remainder = 0
    for character in numeric:
        remainder = (remainder * 10 + int(character)) % 97
    return remainder == 1


def redact_secrets(text: str, limit: int = 4_000) -> str:
    redacted = clean_text(text, max(limit * 2, limit))
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    redacted = _SSN_SHAPE_RE.sub("[REDACTED]", redacted)
    redacted = _PAN_CANDIDATE_RE.sub(
        lambda match: "[REDACTED]" if _luhn_valid(match.group(0)) else match.group(0),
        redacted,
    )
    redacted = _IBAN_CANDIDATE_RE.sub(
        lambda match: "[REDACTED]" if _iban_valid(match.group(0)) else match.group(0),
        redacted,
    )
    redacted = _redact_high_entropy_for_ledger(redacted)
    return redacted[:limit]


def _opaque_token_is_sensitive(token: str) -> bool:
    if len(token) < 20:
        return False
    counts: dict[str, int] = {}
    for character in token:
        counts[character] = counts.get(character, 0) + 1
    entropy = -sum(
        (count / len(token)) * math.log2(count / len(token))
        for count in counts.values()
    )
    classes = sum(
        (
            any(character.islower() for character in token),
            any(character.isupper() for character in token),
            any(character.isdigit() for character in token),
            any(character in "_+/=-" for character in token),
        )
    )
    return (classes >= 3 and entropy >= 3.3) or (len(token) >= 24 and entropy >= 4.0)


def _redact_high_entropy_for_ledger(text: str) -> str:
    def replacement(match: re.Match[str]) -> str:
        context = match.string[max(0, match.start() - 80) : match.start()]
        plausible_digest = bool(
            re.fullmatch(r"(?:[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})", match.group(0))
        )
        digest_label = re.search(
            r"(?i)\b(?:commit|hash|sha|sha256)\s*[:=#]?\s*$", context
        )
        sensitive_label = re.search(
            r"(?i)\b(?:api[_ -]?key|credential|hindsight[_ -]?key|passcode|"
            r"password|pin|secret|token)\b",
            context,
        )
        if plausible_digest and digest_label and not sensitive_label:
            return match.group(0)
        return "[REDACTED_HIGH_ENTROPY]"

    redacted = text
    for pattern in _HIGH_ENTROPY_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return _OPAQUE_TOKEN_RE.sub(
        lambda match: (
            replacement(match)
            if _opaque_token_is_sensitive(match.group(0))
            else match.group(0)
        ),
        redacted,
    )


def redact_for_report(value: Any, limit: int = 1_000) -> str:
    """Flatten model-authored prose and remove likely credentials/opaque tokens."""
    redacted = redact_secrets(clean_text(value, max(limit * 2, limit)), max(limit * 2, limit))
    if contains_raw_error(redacted):
        return "[REDACTED_RAW_ERROR]"
    for pattern in _HIGH_ENTROPY_PATTERNS:
        redacted = pattern.sub("[REDACTED_HIGH_ENTROPY]", redacted)
    redacted = _OPAQUE_TOKEN_RE.sub(
        lambda match: (
            "[REDACTED_HIGH_ENTROPY]"
            if _opaque_token_is_sensitive(match.group(0))
            else match.group(0)
        ),
        redacted,
    )
    redacted = re.sub(r"\s+", " ", redacted).strip()
    redacted = redacted.replace("\\", "\\\\")
    for character in "![]()":
        redacted = redacted.replace(character, f"\\{character}")
    redacted = redacted.replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")
    return redacted[:limit]


def contains_secret(text: str) -> bool:
    if "[REDACTED" in text.upper():
        return True
    if any(pattern.search(text) for pattern in (*_SECRET_PATTERNS, *_HIGH_ENTROPY_PATTERNS)):
        return True
    if _SSN_SHAPE_RE.search(text):
        return True
    if any(_luhn_valid(match.group(0)) for match in _PAN_CANDIDATE_RE.finditer(text)):
        return True
    if any(_iban_valid(match.group(0)) for match in _IBAN_CANDIDATE_RE.finditer(text)):
        return True
    return any(
        _opaque_token_is_sensitive(match.group(0))
        for match in _OPAQUE_TOKEN_RE.finditer(text)
    )


def contains_health_data(text: str) -> bool:
    """Health facts are permitted for this user's strictly scoped memory bank."""
    normalized = clean_text(text, 1_000)
    return bool(
        _HEALTH_DATA_RE.search(normalized)
        or _KNOWN_MEDICATION_RE.search(normalized)
        or _KNOWN_CONDITION_RE.search(normalized)
    )


def contains_raw_error(text: str) -> bool:
    return any(pattern.search(text) for pattern in _RAW_ERROR_PATTERNS)


_SECRET_ARGUMENT_KEY_RE = re.compile(
    r"(?i)(?:api[_ -]?key|authorization|backup[_ -]?code|credential|"
    r"hindsight[_ -]?key|login[_ -]?code|mnemonic|one[_ -]?time[_ -]?code|"
    r"otp|totp|mfa|authenticator[_ -]?(?:code|secret|token)|passcode|passphrase|"
    r"passwd|password|pin|private[_ -]?key|pwd|recovery[_ -]?(?:code|key)|"
    r"recovery[_ -]?phrase|secret|seed[_ -]?phrase|token|2fa[_ -]?code|"
    r"verification[_ -]?code)"
)


def redact_tool_arguments(arguments: str) -> str:
    """Redact structured credentials without erasing non-secret call identity."""
    limit = min(max(len(arguments), 1), 32_000)
    try:
        parsed = json.loads(arguments)
    except (json.JSONDecodeError, TypeError, ValueError):
        return redact_secrets(arguments, limit)

    def scrub(value: Any, key: str | None = None) -> Any:
        if key and _SECRET_ARGUMENT_KEY_RE.search(key):
            return "[REDACTED_SECRET]"
        if isinstance(value, dict):
            return {
                str(item_key): scrub(item_value, str(item_key))
                for item_key, item_value in sorted(
                    value.items(), key=lambda item: str(item[0])
                )
            }
        if isinstance(value, list):
            return [scrub(item) for item in value]
        if isinstance(value, str):
            return redact_secrets(value, min(max(len(value), 1), 8_000))
        return value

    return canonical_json(scrub(parsed))[:32_000]


_MEMORY_OPT_OUT_PATTERNS = (
    re.compile(
        r"(?i)(?:^|[.!?]\s+)(?:and\s+)?(?:please\s+)?"
        r"(?:could|would|can|will)\s+you\s+not\s+"
        r"(?:remember|retain|store|save|keep)\s+"
        r"(?:anything\s+from\s+this\s+message|any\s+(?:details|part)\s+"
        r"(?:from|of)\s+this(?:\s+message)?|any\s+of\s+this|anything|"
        r"this\s+message|this|that|it|the\s+following)\b"
    ),
    re.compile(
        r"(?i)(?:^|[.!?]\s+)(?:and\s+)?i\s+"
        r"(?:(?:do\s+not|don['’]?t)\s+want\s+you\s+to|"
        r"would\s+rather\s+you\s+not)\s+"
        r"(?:remember|retain|store|save|keep)\s+"
        r"(?:anything\s+from\s+this\s+message|any\s+of\s+this|anything|"
        r"this\s+message|this|that|it|the\s+following)\b"
    ),
    re.compile(
        r"(?i)(?:^|[.!?]\s+)(?:and\s+)?(?:please\s+)?avoid\s+"
        r"(?:remembering|retaining|storing|saving|keeping)\s+"
        r"(?:anything\s+from\s+this\s+message|any\s+of\s+this|anything|"
        r"this\s+message|this|that|it|the\s+following)\b"
    ),
    re.compile(
        r"(?i)\b(?:do\s+not|don['’]?t|never)\s+(?:retain|memorize)\s+"
        r"(?:anything\s+from\s+this\s+message|any\s+(?:details|part)\s+"
        r"(?:from|of)\s+this(?:\s+message)?|any\s+of\s+this|anything|"
        r"this\s+message|this|that|it|the\s+following|"
        r"what\s+i\s+(?:said|say|wrote))\b"
    ),
    re.compile(
        r"(?i)\b(?:do\s+not|don['’]?t|never)\s+(?:store|save|record)\s+"
        r"(?:anything\s+from\s+this\s+message|any\s+of\s+this|this\s+message|"
        r"this|that|it|the\s+following)\s+(?:in|to)\s+"
        r"(?:memory|storage)\b"
    ),
    re.compile(
        r"(?i)(?:^|[.!?]\s+)(?:and\s+)?(?:please\s+)?"
        r"(?:do\s+not|don['’]?t|never)\s+remember\s+"
        r"(?:anything\s+from\s+this\s+message|any\s+details\s+from\s+"
        r"this\s+message|any\s+of\s+this|anything|"
        r"this\s+message|this|that|it|the\s+following|"
        r"what\s+i\s+(?:said|say|wrote))\b"
    ),
    re.compile(
        r"(?i)^\s*(?:please\s+)?(?:do\s+not|don['’]?t|never)\s+"
        r"remember\s+my\b"
    ),
    re.compile(
        r"(?i)(?:^|[.!?]\s+)(?:and\s+)?(?:please\s+)?"
        r"(?:do\s+not|don['’]?t|never)\s+remember\s+my\b"
    ),
    re.compile(
        r"(?i)\b(?:do\s+not|don['’]?t|never)\s+(?:add|put)\b.{0,50}"
        r"\b(?:memory|memories)\b"
    ),
    re.compile(
        r"(?i)^\s*(?:please\s+)?(?:do\s+not|don['’]?t|never)\s+keep\s+"
        r"(?:this|that|it|any\s+of\s+this)(?:\s+in\s+(?:memory|storage))?\b"
    ),
    re.compile(
        r"(?i)^\s*(?:please\s+)?(?:(?:can|could|would|will)\s+you\s+)?forget\s+"
        r"(?:anything|everything|my\b|this|that|it|the\s+following|what\s+follows|"
        r"what\s+i\s+(?:said|say|wrote))"
    ),
    re.compile(
        r"(?i)(?:^|[.!?]\s+)(?:and\s+)?(?:please\s+)?forget\s+"
        r"(?:anything|everything|my\b|this|that|it|the\s+following|what\s+follows|"
        r"what\s+i\s+(?:said|say|wrote))"
    ),
    re.compile(r"(?i)\boff[\s-]+the[\s-]+record\b"),
    re.compile(
        r"(?i)\b(?:this|that|it)\s+(?:(?:is|was)\s+not|"
        r"isn['’]?t|wasn['’]?t)\s+for\s+(?:memory|retention|storage)\b"
    ),
    re.compile(
        r"(?i)\bkeep\s+(?:this|that|it|the\s+following)\s+out\s+of\s+"
        r"(?:memory|storage)\b"
    ),
    re.compile(
        r"(?i)(?:^|[.!?]\s+)(?:and\s+)?(?:please\s+)?"
        r"(?:(?:do\s+not|don['’]?t|never)\s+include|exclude)\s+"
        r"(?:this|that|it|the\s+following)\s+(?:in|from)\s+"
        r"(?:memory|storage)\b"
    ),
    re.compile(
        r"(?i)(?:^|[.!?]\s+)(?:and\s+)?(?:please\s+)?"
        r"(?:do\s+not|don['’]?t|never)\s+use\s+"
        r"(?:this|that|it|the\s+following)\s+(?:as|for)\s+"
        r"(?:memory|storage)\b"
    ),
)


def memory_opt_out(text: str) -> bool:
    """Whether the user explicitly prohibited this message from memory storage."""
    normalized = clean_text(text, 4_000)
    return any(pattern.search(normalized) for pattern in _MEMORY_OPT_OUT_PATTERNS)


_TRANSFORMED_CONTENT_FRAMING_RE = re.compile(
    r"(?im)^\s*(?:please\s+)?(?:(?:can|could|would|will)\s+you\s+)?"
    r"(?:clean\s+up|convert|copyedit|edit|paraphrase|"
    r"polish|proofread|reformat|rewrite|summarize|translate|"
    r"review\s+(?:this|the)|fix\s+(?:this|the)?\s*(?:grammar|wording))\b"
    r"[^\n:]{0,120}(?::\s*|\n|[.?!]\s+)|"
    r"^\s*here\s+is\s+(?:the\s+)?(?:text|sentence|draft|content)\s+to\s+"
    r"(?:clean\s+up|convert|copyedit|edit|paraphrase|polish|proofread|reformat|"
    r"rewrite|summarize|translate)\b[^\n:]{0,80}(?::\s*|\n|[.?!]\s+)"
)


def has_transformed_content_framing(text: str) -> bool:
    """Whether following text is material to transform, not a user assertion."""
    return bool(_TRANSFORMED_CONTENT_FRAMING_RE.search(clean_text(text, 4_000)))


_TRANSIENT_MEMORY_SCOPE_RE = re.compile(
    r"(?i)\b(?:for|in|on|during)\s+(?:just\s+)?(?:this|that)(?:\s+one)?\s+"
    r"[a-z][a-z0-9_-]*(?:\s+[a-z][a-z0-9_-]*){0,2}\b"
)
_TEMPORARY_MEMORY_TIME_RE = re.compile(
    r"(?i)\b(?:for\s+now|temporarily|today|tonight|this\s+(?:session|week|month)|"
    r"just\s+this\s+once|for\s+this\s+one|right\s+now|at\s+the\s+moment|"
    r"for\s+the\s+time\s+being|in\s+this\s+conversation|on\s+this\s+occasion|"
    r"for\s+the\s+next\s+(?:\d+|a|an|one|two|few)?\s*"
    r"(?:minutes?|hours?|days?|weeks?|months?)|until\s+[^,.!?;]{2,40}|"
    r"while\s+[^,.!?;]{2,80})\b"
)


def has_transient_memory_scope(text: str) -> bool:
    """Reject deictic one-turn/task scopes that cannot safely become global state."""
    normalized = clean_text(text, 1_000)
    return bool(
        _TRANSIENT_MEMORY_SCOPE_RE.search(normalized)
        or _TEMPORARY_MEMORY_TIME_RE.search(normalized)
    )


_NONASSERTIVE_MEMORY_RE = re.compile(
    r"(?i)^\s*(?:for\s+example|e\.g\.|maybe|perhaps|possibly|hypothetically|"
    r"imagine|assume|consider(?:\s+that)?|suppose|assuming|if\b|"
    r"i\s+(?:think|guess|imagine|wonder|am\s+not\s+sure)\b)|"
    r"\b(?:apparently|appears?|maybe|ostensibly|perhaps|possibly|probably|"
    r"reportedly|seems?|supposedly|likely)\b|"
    r"\bi\s+suppose\s*[.!?]?$|"
    r"\b(?:might|may(?!\s+\d{1,2}\b)|could|would)\b|"
    r"\b(?:try|tries|trying|tried|attempt|attempts|attempting|attempted|hope|hopes|"
    r"hoping|hoped)\s+to\b|"
    r"\b(?:if|unless|provided\s+that|assuming(?:\s+that)?|depending\s+on)\b"
)


def is_nonassertive_memory_statement(text: str) -> bool:
    """Whether a sentence is conditional, speculative, or explicitly uncertain."""
    return bool(_NONASSERTIVE_MEMORY_RE.search(clean_text(text, 1_000)))


_HISTORICAL_MEMORY_RE = re.compile(
    r"(?i)\b(?:used\s+to|formerly|previously|yesterday|last\s+"
    r"(?:week|month|year)|was|were)\b"
)


def is_historical_memory_statement(text: str) -> bool:
    """Whether mutable wording describes prior rather than current state."""
    return bool(_HISTORICAL_MEMORY_RE.search(clean_text(text, 1_000)))


def slug(value: str, limit: int = 96) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", ".", value)
    value = re.sub(r"\.{2,}", ".", value).strip(".-_")
    return (value or "item")[:limit]


def parse_version(value: str | None) -> tuple[int, ...]:
    if not value:
        return ()
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", value)
    return tuple(int(part) for part in match.groups()) if match else ()


def _schema_type_matches(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)


def _validate_json_value(
    value: Any,
    schema: dict[str, Any],
    path: str = "$",
    depth: int = 0,
) -> None:
    """Validate the bounded JSON-Schema subset used by nightly Reflect."""
    if depth > 20:
        raise HindsightError("structured Reflect output exceeds schema nesting limit")
    if not isinstance(schema, dict):
        raise HindsightError(f"invalid response schema at {path}")

    for keyword in ("allOf", "anyOf", "oneOf"):
        branches = schema.get(keyword)
        if branches is None:
            continue
        if not isinstance(branches, list) or not branches:
            raise HindsightError(f"invalid {keyword} schema at {path}")
        matches = 0
        for branch in branches:
            try:
                _validate_json_value(value, branch, path, depth + 1)
            except HindsightError:
                continue
            matches += 1
        if keyword == "allOf" and matches != len(branches):
            raise HindsightError(f"structured Reflect output violates allOf at {path}")
        if keyword == "anyOf" and matches == 0:
            raise HindsightError(f"structured Reflect output violates anyOf at {path}")
        if keyword == "oneOf" and matches != 1:
            raise HindsightError(f"structured Reflect output violates oneOf at {path}")

    if "const" in schema and value != schema["const"]:
        raise HindsightError(f"structured Reflect output violates const at {path}")
    if "enum" in schema:
        enum = schema["enum"]
        if not isinstance(enum, list) or value not in enum:
            raise HindsightError(f"structured Reflect output violates enum at {path}")

    expected = schema.get("type")
    if expected is not None:
        expected_types = [expected] if isinstance(expected, str) else expected
        if (
            not isinstance(expected_types, list)
            or not expected_types
            or not all(isinstance(item, str) for item in expected_types)
        ):
            raise HindsightError(f"invalid type schema at {path}")
        if not any(_schema_type_matches(value, item) for item in expected_types):
            raise HindsightError(f"structured Reflect output has wrong type at {path}")

    if isinstance(value, dict):
        required = schema.get("required", [])
        if not isinstance(required, list) or not all(
            isinstance(item, str) for item in required
        ):
            raise HindsightError(f"invalid required schema at {path}")
        missing = [item for item in required if item not in value]
        if missing:
            raise HindsightError(
                f"structured Reflect output is missing {missing[0]!r} at {path}"
            )
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            raise HindsightError(f"invalid properties schema at {path}")
        additional = schema.get("additionalProperties", True)
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if key in properties:
                _validate_json_value(item, properties[key], child_path, depth + 1)
            elif additional is False:
                raise HindsightError(
                    f"structured Reflect output has unexpected field {key!r} at {path}"
                )
            elif isinstance(additional, dict):
                _validate_json_value(item, additional, child_path, depth + 1)
        minimum = schema.get("minProperties")
        maximum = schema.get("maxProperties")
        if isinstance(minimum, int) and len(value) < minimum:
            raise HindsightError(f"structured Reflect output has too few fields at {path}")
        if isinstance(maximum, int) and len(value) > maximum:
            raise HindsightError(f"structured Reflect output has too many fields at {path}")

    if isinstance(value, list):
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if isinstance(minimum, int) and len(value) < minimum:
            raise HindsightError(f"structured Reflect output has too few items at {path}")
        if isinstance(maximum, int) and len(value) > maximum:
            raise HindsightError(f"structured Reflect output has too many items at {path}")
        item_schema = schema.get("items")
        if item_schema is not None:
            if not isinstance(item_schema, dict):
                raise HindsightError(f"invalid items schema at {path}")
            for index, item in enumerate(value):
                _validate_json_value(item, item_schema, f"{path}[{index}]", depth + 1)

    if isinstance(value, str):
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        if isinstance(minimum, int) and len(value) < minimum:
            raise HindsightError(f"structured Reflect output string is too short at {path}")
        if isinstance(maximum, int) and len(value) > maximum:
            raise HindsightError(f"structured Reflect output string is too long at {path}")
        if "pattern" in schema:
            try:
                matches = re.search(str(schema["pattern"]), value)
            except re.error as exc:
                raise HindsightError(f"invalid pattern schema at {path}") from exc
            if not matches:
                raise HindsightError(f"structured Reflect output violates pattern at {path}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(value):
            raise HindsightError(f"structured Reflect output is not finite at {path}")
        if "minimum" in schema and value < schema["minimum"]:
            raise HindsightError(f"structured Reflect output is below minimum at {path}")
        if "maximum" in schema and value > schema["maximum"]:
            raise HindsightError(f"structured Reflect output is above maximum at {path}")


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


def _validated_base_url() -> str:
    value = os.getenv(
        "NANOBOT_HINDSIGHT_BASE_URL", "http://127.0.0.1:8888"
    ).strip().rstrip("/")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(
            "NANOBOT_HINDSIGHT_BASE_URL must be an absolute http(s) URL"
        )
    if parsed.username or parsed.password:
        raise ValueError("Hindsight credentials must not be embedded in the base URL")
    loopback = parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
    if (
        parsed.scheme == "http"
        and not loopback
        and not env_bool("NANOBOT_HINDSIGHT_ALLOW_INSECURE_HTTP", False)
    ):
        raise ValueError(
            "remote Hindsight endpoints require HTTPS; set "
            "NANOBOT_HINDSIGHT_ALLOW_INSECURE_HTTP=true only for an explicitly "
            "trusted private network"
        )
    return value


def _safe_workspace_state_dir(workspace: Path, configured: Path) -> Path:
    """Resolve relative private state without following workspace symlinks.

    An absolute state path is an explicit operator choice. A relative path may
    originate in a Git-backed workspace, so it must remain beneath that
    workspace lexically and no existing component may be a symlink.
    """
    if configured.is_absolute():
        return configured
    root = workspace.resolve()
    candidate = Path(os.path.abspath(root / configured))
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            "relative NANOBOT_HINDSIGHT_STATE_DIR must stay inside the workspace"
        ) from exc
    current = root
    for component in relative.parts:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(
                "relative NANOBOT_HINDSIGHT_STATE_DIR must not traverse a symlink"
            )
    return candidate


@dataclass(frozen=True)
class Settings:
    workspace: Path
    base_url: str
    bank_id: str
    api_key: str | None
    mode: str
    user_tag: str | None
    single_user_bank: bool
    single_user_gateway: bool
    project_tag: str | None
    tags_match: str
    recall_max_tokens: int
    recall_timeout_seconds: int
    background_timeout_seconds: int
    nightly_reflect: bool
    nightly_cron: str
    timezone: str
    state_dir: Path
    report_dir: Path
    skill_roots: tuple[Path, ...]
    max_sessions: int
    max_exchanges: int
    capture_lookback_days: int

    @classmethod
    def from_env(cls, workspace: Path, default_timezone: str = "UTC") -> "Settings":
        mode = os.getenv("NANOBOT_HINDSIGHT_MODE", "observe").strip().lower()
        if mode not in {"off", "observe", "retain"}:
            mode = "observe"

        raw_roots = os.getenv("NANOBOT_HINDSIGHT_SKILL_ROOTS", "skills")
        roots: list[Path] = []
        for item in raw_roots.split(os.pathsep):
            item = item.strip()
            if not item:
                continue
            path = Path(item)
            roots.append(path if path.is_absolute() else workspace / path)

        state_raw = Path(os.getenv("NANOBOT_HINDSIGHT_STATE_DIR", ".nanobot-hindsight"))
        report_raw = Path(os.getenv("NANOBOT_HINDSIGHT_REPORT_DIR", "reports/hindsight-nightly"))
        state_dir = _safe_workspace_state_dir(workspace, state_raw)
        report_dir = report_raw if report_raw.is_absolute() else workspace / report_raw

        tags_match = os.getenv("NANOBOT_HINDSIGHT_TAGS_MATCH", "all_strict").strip()
        if tags_match not in {"any", "all", "any_strict", "all_strict"}:
            tags_match = "all_strict"

        return cls(
            workspace=workspace,
            base_url=_validated_base_url(),
            bank_id=os.getenv("HINDSIGHT_BANK_ID", "").strip(),
            api_key=os.getenv("HINDSIGHT_API_KEY") or None,
            mode=mode,
            user_tag=os.getenv("NANOBOT_HINDSIGHT_USER_TAG") or None,
            single_user_bank=env_bool(
                "NANOBOT_HINDSIGHT_SINGLE_USER_BANK", False
            ),
            single_user_gateway=env_bool(
                "NANOBOT_HINDSIGHT_SINGLE_USER_GATEWAY", False
            ),
            project_tag=os.getenv("NANOBOT_HINDSIGHT_PROJECT_TAG") or None,
            tags_match=tags_match,
            recall_max_tokens=env_int("NANOBOT_HINDSIGHT_RECALL_MAX_TOKENS", 900, 200, 2_000),
            recall_timeout_seconds=env_int("NANOBOT_HINDSIGHT_RECALL_TIMEOUT", 4, 1, 20),
            background_timeout_seconds=env_int("NANOBOT_HINDSIGHT_BACKGROUND_TIMEOUT", 45, 5, 180),
            nightly_reflect=env_bool("NANOBOT_HINDSIGHT_NIGHTLY_REFLECT", True),
            nightly_cron=os.getenv("NANOBOT_HINDSIGHT_NIGHTLY_CRON", "0 3 * * *").strip(),
            timezone=os.getenv("NANOBOT_HINDSIGHT_TIMEZONE", default_timezone).strip() or "UTC",
            state_dir=state_dir,
            report_dir=report_dir,
            skill_roots=tuple(roots),
            max_sessions=env_int("NANOBOT_HINDSIGHT_MAX_SESSIONS", 40, 1, 500),
            max_exchanges=env_int("NANOBOT_HINDSIGHT_MAX_EXCHANGES", 80, 1, 500),
            capture_lookback_days=env_int(
                "NANOBOT_HINDSIGHT_CAPTURE_LOOKBACK_DAYS", 3, 1, 30
            ),
        )

    @property
    def tags(self) -> list[str]:
        return [tag for tag in (self.user_tag, self.project_tag) if tag]

    @property
    def configured(self) -> bool:
        return bool(self.bank_id and self.base_url)

    @property
    def automation_configured(self) -> bool:
        """Whether unattended capture and memory access are scoped to one user."""
        if not self.configured or not self.single_user_gateway:
            return False
        if self.single_user_bank:
            return True
        stable_user_tag = bool(
            self.user_tag
            and re.fullmatch(r"user:[A-Za-z0-9][A-Za-z0-9._-]{0,127}", self.user_tag)
        )
        return stable_user_tag and self.tags_match == "all_strict"

    @property
    def ledger_scope_fingerprint(self) -> str:
        """Bind private checkpoints to one bank/user/project destination."""
        return stable_hash(
            {
                "base_url": self.base_url,
                "bank_id": self.bank_id,
                "user_scope": self.user_tag or (
                    "single-user-bank" if self.single_user_bank else "unscoped"
                ),
                "project_tag": self.project_tag or "",
            }
        )


class HindsightError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None, body: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.body = body


@dataclass(frozen=True)
class DryRunResult:
    supported: bool
    facts: tuple[dict[str, Any], ...] = ()


class HindsightClient:
    """Small async wrapper around Hindsight's v0.8.6 REST surface."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._api_version: str | None = None
        self._dry_run_supported: bool | None = None

    def _require_automation_scope(self) -> None:
        if not self.settings.automation_configured:
            raise HindsightError(
                "automatic Hindsight access requires an explicitly single-user gateway "
                "and either NANOBOT_HINDSIGHT_USER_TAG or a single-user bank"
            )

    def _url(self, path: str) -> str:
        bank = urllib.parse.quote(self.settings.bank_id, safe="")
        return f"{self.settings.base_url}{path.format(bank_id=bank)}"

    def _request_sync(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        timeout: int,
    ) -> dict[str, Any]:
        if not self.settings.configured:
            raise HindsightError("Hindsight bank is not configured")
        data = canonical_json(payload).encode("utf-8") if payload is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.settings.api_key:
            headers["Authorization"] = f"Bearer {self.settings.api_key}"
        request = urllib.request.Request(self._url(path), data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
                parsed = json.loads(body) if body else {}
                if not isinstance(parsed, dict):
                    raise HindsightError("Hindsight returned a non-object response")
                return parsed
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:2_000]
            raise HindsightError(
                f"Hindsight HTTP {exc.code}", status=exc.code, body=body
            ) from exc
        except urllib.error.URLError as exc:
            raise HindsightError(f"Hindsight connection failed: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise HindsightError("Hindsight returned invalid JSON") from exc

    async def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        effective_timeout = timeout or self.settings.background_timeout_seconds
        return await asyncio.to_thread(
            self._request_sync, method, path, payload, effective_timeout
        )

    async def version(self) -> str:
        if self._api_version is None:
            response = await self._request("GET", "/version", timeout=self.settings.recall_timeout_seconds)
            self._api_version = str(response.get("api_version") or response.get("version") or "unknown")
        return self._api_version

    async def recall(self, query: str) -> list[dict[str, Any]]:
        self._require_automation_scope()
        payload: dict[str, Any] = {
            "query": clean_text(query, 2_000),
            "types": ["world", "experience", "observation"],
            "prefer_observations": True,
            "budget": "low",
            "max_tokens": self.settings.recall_max_tokens,
            "include": {"entities": None},
            "query_timestamp": utc_now(),
        }
        if self.settings.tags:
            payload["tags"] = self.settings.tags
            payload["tags_match"] = self.settings.tags_match
        response = await self._request(
            "POST",
            "/v1/default/banks/{bank_id}/memories/recall",
            payload,
            timeout=self.settings.recall_timeout_seconds,
        )
        results = response.get("results") or []
        return [item for item in results if isinstance(item, dict)]

    async def dry_run_extract(self, content: str, context: str) -> DryRunResult:
        if self._dry_run_supported is False:
            return DryRunResult(supported=False)
        mission = (
            "Extract only durable user preferences or constraints; identity and people; "
            "named projects and current commitments; explicitly stated health conditions, "
            "diagnoses, medications, allergies, and providers; decisions and dated events "
            "including health events; open issues; or a solution proven by successful "
            "verification. Ignore greetings, research, sources, raw tool output, stack traces, "
            "speculation, and temporary execution state."
        )
        payload = {
            "content": clean_text(content, 5_000),
            "context": clean_text(context, 1_000),
            "timestamp": utc_now(),
            "agent_name": "nanobot",
            "retain_mission": mission,
            "retain_extraction_mode": "concise",
        }
        try:
            response = await self._request(
                "POST",
                "/v1/default/banks/{bank_id}/memories/dry-run-extract",
                payload,
            )
        except HindsightError as exc:
            if exc.status == 404:
                self._dry_run_supported = False
                return DryRunResult(supported=False)
            raise
        self._dry_run_supported = True
        facts = response.get("facts") or []
        return DryRunResult(
            supported=True,
            facts=tuple(fact for fact in facts if isinstance(fact, dict)),
        )

    async def retain(self, candidate: "Candidate", exchange: "Exchange") -> str:
        self._require_automation_scope()
        version = await self.version()
        if parse_version(version) < MIN_HINDSIGHT_VERSION:
            raise HindsightError(
                f"Hindsight {version} is too old for this Retain integration; "
                "v0.8.6 or newer is required"
            )

        def build_item(
            *, content: str, document_id: str, category: str
        ) -> dict[str, Any]:
            item: dict[str, Any] = {
                "content": content,
                "context": (
                    f"Nanobot durable-memory checkpoint. Source evidence "
                    f"{exchange.evidence_id}. User statements are attributed to the "
                    "user; assistant resolutions were accepted only when tool evidence "
                    "verified them."
                ),
                "timestamp": exchange.observed_at,
                "metadata": {
                    "source": "nanobot-hindsight",
                    "evidence_id": exchange.evidence_id,
                    "category": category,
                    "gate_version": str(SCHEMA_VERSION),
                },
                "document_id": document_id,
                "tags": [*self.settings.tags, "kind:durable", f"category:{category}"],
                "update_mode": "replace",
            }
            if self.settings.user_tag:
                scopes: list[list[str]] = [[self.settings.user_tag]]
                if self.settings.project_tag:
                    scopes.append([self.settings.user_tag, self.settings.project_tag])
                item["observation_scopes"] = scopes
            elif self.settings.single_user_bank:
                item["observation_scopes"] = "shared"
            return item

        async def store(item: dict[str, Any]) -> None:
            response = await self._request(
                "POST",
                "/v1/default/banks/{bank_id}/memories",
                {"items": [item], "async": False},
            )
            if not (
                response.get("success") is True
                and response.get("async") is False
                and response.get("items_count") == 1
            ):
                raise HindsightError(
                    "Hindsight did not confirm one synchronous Retain item",
                    body=clean_text(response, 1_000),
                )

        # Close an earlier mutable open-issue document before storing the
        # immutable resolution event.  If the second write fails, retrying is
        # safe and the bank never remains stuck recalling an issue as open.
        if candidate.category == "resolved_error":
            issue_key = verified_issue_memory_key(exchange)
            resolution = exchange.verified_resolution_sentence
            if issue_key and resolution:
                await store(
                    build_item(
                        content=(
                            "Issue closed after verification: "
                            f"{clean_text(resolution, 240)}"
                        ),
                        document_id=scoped_memory_document_id(
                            self.settings, memory_document_id(issue_key)
                        ),
                        category="open_issue",
                    )
                )

        document_id = scoped_memory_document_id(
            self.settings, candidate.document_id
        )
        await store(
            build_item(
                content=candidate.content,
                document_id=document_id,
                category=candidate.category,
            )
        )
        return document_id

    async def operation(self, operation_id: str) -> dict[str, Any]:
        operation = urllib.parse.quote(operation_id, safe="")
        return await self._request(
            "GET",
            f"/v1/default/banks/{{bank_id}}/operations/{operation}",
        )

    async def reflect(self, query: str) -> str:
        self._require_automation_scope()
        payload: dict[str, Any] = {
            "query": clean_text(query, 8_000),
            "budget": "low",
            "max_tokens": 1_200,
            "include": {"facts": {}, "tool_calls": {"output": False}},
            "apply_all_directives": True,
        }
        if self.settings.tags:
            payload["tags"] = self.settings.tags
            payload["tags_match"] = self.settings.tags_match
        response = await self._request(
            "POST", "/v1/default/banks/{bank_id}/reflect", payload
        )
        return clean_text(response.get("text"), 6_000)

    async def reflect_structured(
        self,
        query: str,
        response_schema: dict[str, Any],
    ) -> dict[str, Any]:
        """Run Reflect with a JSON schema and return only validated object output.

        Reflect has no Nanobot tools, so this is the isolation boundary used by
        the nightly reviewer.  The caller must still validate every returned
        finding and memory candidate against its local evidence ledger.
        """
        self._require_automation_scope()
        if not isinstance(response_schema, dict):
            raise TypeError("response_schema must be a JSON-schema object")
        if len(canonical_json(response_schema)) > 32_000:
            raise ValueError("response_schema is too large")
        payload: dict[str, Any] = {
            "query": clean_text(query, 24_000),
            "budget": "low",
            "max_tokens": 1_800,
            "include": {"facts": {}, "tool_calls": {"output": False}},
            "apply_all_directives": False,
            "response_schema": response_schema,
        }
        if self.settings.tags:
            payload["tags"] = self.settings.tags
            payload["tags_match"] = self.settings.tags_match
        response = await self._request(
            "POST", "/v1/default/banks/{bank_id}/reflect", payload
        )
        structured = response.get("structured_output")
        if isinstance(structured, str):
            try:
                structured = json.loads(structured)
            except json.JSONDecodeError as exc:
                raise HindsightError(
                    "Hindsight Reflect returned invalid structured JSON"
                ) from exc
        if not isinstance(structured, dict):
            raise HindsightError(
                "Hindsight Reflect did not return a structured object"
            )
        _validate_json_value(structured, response_schema)
        return structured


@dataclass
class ToolEvent:
    sequence: int
    tool_name: str
    call_id: str
    status: str
    args_fingerprint: str
    excerpt: str = ""
    skill_refs: list[str] = field(default_factory=list)


_ISSUE_TERMS_RE = re.compile(
    r"(?i)\b(?:bug|error|issue|broken|failing|failed|blocked|doesn.t work|unresolved)\b"
)
_RESOLUTION_TERMS_RE = re.compile(
    r"(?i)\b(?:fixed|resolved|working now|passes|passed|verified|successful)\b"
)
_SPECULATIVE_RESOLUTION_RE = re.compile(
    r"(?i)\b(?:apparently|appears?|could|if|likely|may|might|perhaps|possible|"
    r"possibly|potential|probably|seems?|should|try|untested)\b"
)
_NEGATED_RESOLUTION_RE = re.compile(
    r"(?i)(?:\b(?:can.t|cannot|didn.t|failed to|isn.t|not|wasn.t|won.t)\b"
    r".{0,32}\b(?:fixed|resolved|working|passes|passed|verified|successful)\b|"
    r"\b(?:unresolved|persists?|remains?)\b|"
    r"\bstill\s+(?:blocked|broken|failing)\b|"
    r"\b(?:but|however)\b.{0,80}\b(?:blocked|broken|failing|failed|issue|"
    r"persists?|remains?|unresolved)\b|"
    r"\b(?:current|latest|now)\b.{0,48}\b(?:blocked|broken|failed|failing|"
    r"persists?|unresolved)\b)"
)
_CONTRAST_RESOLUTION_RE = re.compile(
    r"(?i)\b(?:although|but|except|however|though|yet)\b"
)
_RESOLUTION_STOP_WORDS = {
    "assistant", "blocked", "broken", "bug", "error", "failed", "failing",
    "fixed", "issue", "passed", "passes", "resolved", "successful", "test",
    "tests", "the", "this", "unresolved", "user", "verified", "working",
}


def _resolution_topic_tokens(text: str) -> set[str]:
    return {
        _normalize_topic_token(token)
        for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9_-]{2,}", text.lower())
        if _normalize_topic_token(token) not in _RESOLUTION_STOP_WORDS
    }


def _is_current_issue_sentence(sentence: str) -> bool:
    lowered = sentence.lower().replace("’", "'")
    direct_inability = bool(
        re.search(
            r"\bi\s+(?:cannot|can't)\s+(?:log\s+in|.{0,60}\b(?:connect|open|"
            r"run|start|get\s+.{0,30}\s+to\s+work|work)\b)",
            lowered,
        )
    )
    if not _ISSUE_TERMS_RE.search(sentence) and not direct_inability:
        return False
    if _QUESTION_RE.search(sentence) or re.match(
        r"^\s*(?:please\s+)?(?:analyze|check|explain|find|fix|inspect|investigate|"
        r"research|review|search|summarize|test)\b",
        lowered,
    ):
        return False
    if re.search(
        r"(?i)\b(?:never saw|did not see|didn.t see|haven.t seen|no longer|without)\b"
        r".{0,40}\b(?:bug|error|issue|failure)\b",
        sentence,
    ):
        return False
    if re.search(
        r"(?i)\b(?:bug|error|issue|failure)\b.{0,32}"
        r"\b(?:isn.t present|not present|no longer|was resolved)\b",
        sentence,
    ):
        return False
    if _RESOLUTION_TERMS_RE.search(sentence) and not re.search(
        r"(?i)\b(?:blocked|failed|failing|persists?|returned|unresolved)\b", sentence
    ):
        return False
    return True


def _is_affirmative_resolution_sentence(sentence: str) -> bool:
    if "?" in sentence:
        return False
    if not _RESOLUTION_TERMS_RE.search(sentence):
        return False
    if (
        _SPECULATIVE_RESOLUTION_RE.search(sentence)
        or _NEGATED_RESOLUTION_RE.search(sentence)
        or _CONTRAST_RESOLUTION_RE.search(sentence)
    ):
        return False
    if re.search(r"(?i)\bpass(?:ed|es)\b", sentence) and not re.search(
        r"(?i)(?:\b(?:tests?|checks?|verification|build|suite)\b.{0,40}"
        r"\bpass(?:ed|es)\b|\bpass(?:ed|es)\b.{0,40}"
        r"\b(?:tests?|checks?|verification|build|suite)\b)",
        sentence,
    ):
        # "The issue was passed to another team" is a hand-off, not a fix.
        if not re.search(r"(?i)\b(?:fixed|resolved|successful|verified|working now)\b", sentence):
            return False
    return True


def _tool_can_verify_resolution(tool_name: str) -> bool:
    """Reject read/research tools whose recovery cannot prove the task was fixed."""
    tokens = {
        token
        for token in re.split(r"[^a-z0-9]+", clean_text(tool_name, 100).lower())
        if token
    }
    non_verifying = {
        "browse", "browser", "fetch", "find", "open", "read", "recall",
        "reflect", "search", "view", "web",
    }
    return bool(tokens) and not tokens.intersection(non_verifying)


@dataclass
class Exchange:
    evidence_id: str
    session_key: str
    observed_at: str
    user_text: str
    assistant_final: str
    tool_events: list[ToolEvent]
    source: str = "session_history"
    coverage: str = "public_only"

    @property
    def skill_refs(self) -> set[str]:
        refs: set[str] = set()
        for event in self.tool_events:
            refs.update(event.skill_refs)
        return refs

    @property
    def has_tool_error(self) -> bool:
        return any(event.status == "error" for event in self.tool_events)

    @property
    def has_verified_success(self) -> bool:
        return any(event.status == "success" for event in self.tool_events)

    @property
    def verified_resolution_sentence(self) -> str | None:
        has_matching_verification = any(
            success.sequence > failure.sequence
            and success.tool_name != "unknown"
            and _tool_can_verify_resolution(success.tool_name)
            and success.tool_name == failure.tool_name
            and success.args_fingerprint == failure.args_fingerprint
            for failure in self.tool_events
            if failure.status == "error"
            for success in self.tool_events
            if success.status == "success"
        )
        if not has_matching_verification:
            return None
        issue_sentences = [
            sentence
            for sentence in _sentences(self.user_text)
            if _is_current_issue_sentence(sentence)
        ]
        if not issue_sentences:
            return None
        issue_topics = [
            _resolution_topic_tokens(sentence) for sentence in issue_sentences
        ]
        candidates: list[tuple[int, int, str]] = []
        for index, sentence in enumerate(_sentences(self.assistant_final)):
            if not _is_affirmative_resolution_sentence(sentence):
                continue
            sentence_topics = _resolution_topic_tokens(sentence)
            overlap = max(
                (len(sentence_topics.intersection(topic)) for topic in issue_topics),
                default=0,
            )
            if overlap:
                candidates.append((overlap, -index, sentence))
        return max(candidates)[2] if candidates else None

    @property
    def verified_resolution(self) -> bool:
        return self.verified_resolution_sentence is not None


@dataclass
class Candidate:
    candidate_id: str
    evidence_id: str
    category: str
    content: str
    memory_key: str | None
    confidence: float
    verified: bool
    sensitivity: str = "normal"
    status: str = "proposed"
    reason: str = ""
    operation_id: str | None = None

    @property
    def document_id(self) -> str:
        if self.memory_key:
            return memory_document_id(self.memory_key)
        return f"nanobot:event:{self.candidate_id[:32]}"

    @classmethod
    def build(
        cls,
        *,
        exchange: Exchange,
        category: str,
        content: str,
        confidence: float,
        verified: bool,
        memory_key: str | None = None,
        derive_key: bool = False,
    ) -> "Candidate":
        normalized = clean_text(content, 280)
        if derive_key and category in MUTABLE_CATEGORIES and not memory_key:
            memory_key = derive_memory_key(category, normalized)
        candidate_id = stable_hash(
            {
                "evidence_id": exchange.evidence_id,
                "category": category,
                "content": normalized.lower(),
                "memory_key": memory_key,
            }
        )
        return cls(
            candidate_id=candidate_id,
            evidence_id=exchange.evidence_id,
            category=category,
            content=normalized,
            memory_key=memory_key,
            confidence=confidence,
            verified=verified,
        )


def derive_memory_key(category: str, text: str) -> str:
    words = [
        word.lower()
        for word in re.findall(r"[A-Za-z0-9][A-Za-z0-9_-]*", text)
        if word.lower()
        not in {
            "the", "a", "an", "and", "or", "to", "of", "in", "on", "for", "is",
            "are", "was", "were", "user", "stated", "that", "this", "my", "i",
        }
    ]
    topic = ".".join(words[:8]) or stable_hash(text)[:16]
    return f"{category}.{topic}"


def memory_document_id(memory_key: str) -> str:
    """Map a canonical key to a compact, collision-resistant document ID."""
    return (
        f"nanobot:durable:{slug(memory_key, 60)}:"
        f"{stable_hash(memory_key)[:16]}"
    )


def scoped_memory_document_id(settings: Settings, logical_document_id: str) -> str:
    """Namespace a Hindsight document upsert to one configured user scope."""
    scope = {
        "bank_id": settings.bank_id,
        "user_tag": settings.user_tag or "single-user-bank",
        "project_tag": settings.project_tag or "",
    }
    return f"{logical_document_id}:scope:{stable_hash(scope)[:16]}"


def _memory_key_error(category: str, memory_key: str | None) -> str | None:
    value = memory_key or ""
    if len(value) > 96 or not re.fullmatch(
        rf"{re.escape(category)}\.[a-z0-9][a-z0-9._-]+",
        value,
    ):
        return "mutable memory_key must be category-namespaced and canonical"
    if slug(value, 96) != value:
        return "mutable memory_key must not contain repeated or trailing punctuation"
    return None
