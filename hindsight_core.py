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
