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


class CandidatePolicy:
    """Conservative deterministic gate applied after model extraction."""

    minimum_confidence = 0.78

    def validate(self, candidate: Candidate, exchange: Exchange) -> str | None:
        if memory_opt_out(exchange.user_text):
            return "the user explicitly opted this message out of memory storage"
        if has_transformed_content_framing(exchange.user_text):
            return "text supplied for transformation is not a direct user assertion"
        if has_transient_memory_scope(exchange.user_text):
            return "task-local or deictic wording is not durable memory"
        if candidate.category not in ALLOWED_CATEGORIES:
            return "category is not allowed"
        if candidate.evidence_id != exchange.evidence_id:
            return "candidate references the wrong exchange"
        if not 5 <= len(candidate.content) <= 280:
            return "content must be between 5 and 280 characters"
        if (
            not math.isfinite(candidate.confidence)
            or candidate.confidence < self.minimum_confidence
        ):
            return "confidence is below the retention threshold"
        source_sentence = closest_source_sentence(exchange.user_text, candidate.content)
        if is_nonassertive_memory_statement(source_sentence):
            return "conditional or speculative wording is not durable memory"
        if is_reported_or_denied_assertion(source_sentence):
            return "reported, attributed, or denied text is not a direct user assertion"
        if contains_secret(candidate.content) or candidate.sensitivity == "secret":
            return "secrets or sensitive content are never retained automatically"
        if candidate.sensitivity not in {"normal", "sensitive"}:
            return "candidate sensitivity is invalid"
        health_scoped_key = bool(
            candidate.category == "durable_fact"
            and candidate.memory_key
            and candidate.memory_key.startswith("durable_fact.health.")
        )
        if (
            candidate.sensitivity == "sensitive"
            and not contains_health_data(candidate.content)
            and not health_scoped_key
        ):
            return "non-health sensitive content is never retained automatically"
        if contains_raw_error(candidate.content):
            return "raw error output is not durable memory"
        if (
            candidate.category in MUTABLE_CATEGORIES
            and is_historical_memory_statement(source_sentence)
            and not (
                health_scoped_key
                and (
                    re.search(
                        r"(?i)\bi\s+(?:was|have\s+been)\s+diagnosed\s+with\b",
                        source_sentence,
                    )
                    or candidate.memory_key.endswith(".history")
                )
            )
        ):
            return "historical wording must not replace current mutable memory"
        if candidate.category in MUTABLE_CATEGORIES and not candidate.memory_key:
            return "mutable memories require a stable memory_key"
        if candidate.category in MUTABLE_CATEGORIES:
            expected_key = canonical_memory_key(
                candidate.category, candidate.content
            )
            if expected_key is None:
                return "mutable topic has no locally supported canonical memory_key"
            if candidate.memory_key != expected_key:
                return (
                    "mutable memory_key must equal the locally derived canonical key "
                    f"{expected_key}"
                )
            memory_key_error = _memory_key_error(
                candidate.category, candidate.memory_key
            )
            if memory_key_error:
                return memory_key_error
        if candidate.category not in MUTABLE_CATEGORIES and candidate.memory_key:
            return "immutable memories must not supply a memory_key"
        if candidate.category != "resolved_error":
            source_category = direct_user_category(source_sentence)
            if source_category != candidate.category:
                return "candidate category is not supported by the closest user statement"
            expected = f"User stated: {clean_text(source_sentence, 250)}"
            if candidate.content != expected:
                return "candidate content must equal the exact redacted user statement"
        if candidate.category == "open_issue" and not re.search(
            r"(?i)\b(?:bug|error|issue|broken|failing|failed|blocked|cannot|"
            r"can.t|doesn.t work|unresolved)\b",
            exchange.user_text,
        ):
            return "open issues require direct issue evidence"
        if candidate.category == "resolved_error":
            resolution = exchange.verified_resolution_sentence
            if not resolution:
                return (
                    "a resolution requires a correlated failure, successful verification, "
                    "and an affirmative outcome tied to the user issue"
                )
            expected = f"Verified resolution: {clean_text(resolution, 245)}"
            if candidate.content != expected:
                return "resolution content must equal the canonical verified outcome"
        if not candidate.verified:
            return "candidate is not verified"
        return None

    def from_model(self, raw: dict[str, Any], exchange: Exchange) -> tuple[Candidate | None, str | None]:
        try:
            category = str(raw.get("category") or "").strip()
            confidence = float(raw.get("confidence", 0))
            content = str(raw.get("content") or "").strip()
            memory_key = str(raw.get("memory_key") or "").strip() or None
            verified = bool(raw.get("verified", False))
            sensitivity = str(raw.get("sensitivity") or "normal").strip()
        except (TypeError, ValueError):
            return None, "candidate fields have invalid types"
        candidate = Candidate.build(
            exchange=exchange,
            category=category,
            content=content,
            confidence=confidence,
            verified=verified,
            memory_key=memory_key,
            derive_key=False,
        )
        candidate.sensitivity = sensitivity
        reason = self.validate(candidate, exchange)
        return (None, reason) if reason else (candidate, None)


def _strip_nonassertion_blocks(text: str) -> str:
    cleaned = re.sub(r"(?s)```.*?```|~~~.*?~~~", " ", text)
    kept_lines: list[str] = []
    transcript = re.compile(
        r"^\s*(?:>|(?:assistant|claude|code|example|log|nanobot|quote|speaker\s+\d+|"
        r"system|tool|transcript|user)\s*:)",
        re.I,
    )
    for line in cleaned.splitlines():
        if transcript.match(line):
            continue
        if re.match(r"^\s*(?:def|class|import|from)\s+", line):
            continue
        kept_lines.append(line)
    cleaned = "\n".join(kept_lines)
    cleaned = re.sub(r'[`“"][^`”"\n]{2,}[`”"]', " ", cleaned)
    cleaned = re.sub(r"‘[^’\n]{2,}’", " ", cleaned)
    cleaned = re.sub(r"(?<!\w)'[^'\n]{3,}'(?!\w)", " ", cleaned)
    return clean_text(cleaned, 4_000)


def _is_direct_preference_assertion(assertion: str) -> bool:
    lowered = assertion.lower()
    if re.search(
        r"\b(?:article|claude|example|someone|they|you)\b.{0,40}"
        r"\b(?:claimed|inferred|said|says)\b|\bnever\s+said\b|"
        r"\b(?:that|this)\s+is\s+wrong\b",
        lowered,
    ):
        return False
    return bool(
        re.match(
            r"^\s*(?:(?:actually|currently|generally|normally|personally|"
            r"temporarily|for\s+now)\s*,?\s+)?"
            r"(?:i\s+(?:prefer|like|dislike|don.t\s+want|do\s+not\s+want)\b|"
            r"my\s+preference\b)",
            lowered,
        )
        or re.match(
            r"^\s*for\s+(?:(?:the\s+)?[a-z0-9_-]+\s+"
            r"(?:project|repo|repository|workspace)|"
            r"(?:project|repo|repository|workspace)\s+[a-z0-9_-]+)\s*,?\s+"
            r"i\s+prefer\b",
            lowered,
        )
    )


_REPORTED_OR_DENIED_ASSERTION_RE = re.compile(
    r"^\s*(?:(?i:according\s+to\b)|"
    r"(?i:i\s+(?:learned|read|saw|was\s+told)\s+that\b)|"
    r"(?i:(?:i|we|you|he|she|they|someone|my\s+(?:wife|husband|partner|"
    r"spouse|friend|doctor|clinician|provider))\s+"
    r"(?:alleges?|alleged|argues?|argued|asserts?|asserted|claims?|claimed|"
    r"assumes?|assumed|believes?|believed|hears?|heard|infers?|inferred|"
    r"mentions?|mentioned|thinks?|thought|"
    r"reports?|reported|said|say|says|states?|stated|suggests?|suggested|"
    r"writes?|wrote)\b)|"
    r"(?i:(?:(?:a|an|the|my)\s+)?(?:app|article|chart|docs?|document|"
    r"documentation|email|example|guide|lab\s+report|manual|message|model|"
    r"output|page|paper|post|record|report|result|sample|source|study|system|"
    r"test|transcript|website|bot\s+output)\s+"
    r"(?:alleges?|alleged|argues?|argued|asserts?|asserted|claims?|claimed|"
    r"assumes?|assumed|believes?|believed|"
    r"indicates?|indicated|lists?|listed|mentions?|mentioned|notes?|noted|"
    r"predicts?|predicted|reports?|reported|said|say|says|shows?|showed|"
    r"states?|stated|suggests?|suggested|"
    r"writes?|wrote)\b)|"
    r"[A-Z][A-Za-z'’_-]{1,40}(?:\s+[A-Z][A-Za-z'’_-]{1,40}){0,3}\s+"
    r"(?i:assumes?|assumed|believes?|believed|claims?|claimed|indicates?|"
    r"indicated|mentions?|mentioned|notes?|noted|thinks?|thought|"
    r"reports?|reported|said|say|says|states?|stated|suggests?|suggested|"
    r"writes?|wrote)\b|"
    r"(?i:i\s+(?:never\s+said|did\s+not\s+say|didn.t\s+say)\b)|"
    r"(?i:it\s+is\s+(?:false|not\s+true)\s+that\b))|"
    r"(?i:^\s*rumou?r\s+has\s+it\b)|"
    r"(?i:\b(?:you\s+inferred|someone\s+claimed)\b.{0,100}"
    r"\b(?:incorrect|not\s+true|wrong)\b)"
)


def is_reported_or_denied_assertion(text: str) -> bool:
    """Reject attributed, example, transcript, and explicitly denied speech."""
    normalized = clean_text(text, 1_000)
    normalized = re.sub(
        r"(?i)^\s*(?:for\s+context|for\s+reference|fyi|by\s+the\s+way|"
        r"just\s+for\s+context|as\s+background)"
        r"\s*[:,;\-]?\s*",
        "",
        normalized,
    )
    if re.match(
        r"(?i)^\s*(?:that\s+is\s+false\b|contrary\s+to\s+(?:the\s+)?"
        r"(?:report|source|article|email|message)\b)",
        normalized,
    ):
        return True
    return bool(_REPORTED_OR_DENIED_ASSERTION_RE.search(normalized))


def direct_user_category(text: str) -> str | None:
    assertion = _strip_nonassertion_blocks(text)
    if not assertion:
        return None
    lowered = assertion.lower().replace("’", "'")
    # Mobile keyboards commonly produce curly apostrophes.  Expand only the
    # first-person contractions used by the durable-category grammar so the
    # rest of the policy still evaluates the original assertion verbatim.
    lowered = re.sub(r"\bi'm\b", "i am", lowered)
    lowered = re.sub(r"\bwe're\b", "we are", lowered)
    lowered = re.sub(r"\bi've\b", "i have", lowered)
    lowered = re.sub(r"\bwe've\b", "we have", lowered)
    lowered = re.sub(r"\bi'll\b", "i will", lowered)
    lowered = re.sub(r"\bwe'll\b", "we will", lowered)
    if is_reported_or_denied_assertion(assertion):
        return None
    if is_nonassertive_memory_statement(assertion):
        return None
    if _QUESTION_RE.search(assertion) or re.match(
        r"^\s*(?:please\s+)?(?:analyze|check|compare|explain|find|fix|inspect|"
        r"investigate|look\s+up|research|review|search|summarize|test|update)\b",
        lowered,
    ):
        return None
    if re.search(
        r"\b(?:i\s+am|we\s+are)\s+(?:not|no\s+longer)\s+"
        r"(?:blocked|experiencing)\b|"
        r"\b(?:i|we)\s+have\s+no\b.{0,60}\b(?:bug|error|issue|failure)\b",
        lowered,
    ):
        return None
    if re.search(
        r"\b(?:my|our)\s+(?:project|repo|repository|workspace)\b.{0,80}"
        r"\b(?:is|are)\s+not\s+(?:blocked|broken|failing)\b",
        lowered,
    ):
        return None
    if (
        re.search(
            r"\bmy\s+[a-z0-9_-]+(?:\s+[a-z0-9_-]+){0,4}\s+"
            r"(?:is|keeps?\s+getting)\s+(?:blocked|broken|failing)\b|"
            r"\bmy\s+[a-z0-9_-]+(?:\s+[a-z0-9_-]+){0,4}\s+"
            r"(?:doesn.t|does\s+not)\s+work\b",
            lowered,
        )
        or re.search(
            r"\bi\s+(?:cannot|can.t)\s+(?:log\s+in|.{0,60}\b(?:connect|open|"
            r"run|start|to\s+work|work)\b)",
            lowered,
        )
        or re.search(
            r"\bi\s+need\s+to\s+fix\b.{0,80}\b(?:bug|error|issue)\b",
            lowered,
        )
    ):
        return "open_issue" if _is_current_issue_sentence(assertion) else None
    if _is_direct_preference_assertion(assertion):
        return "preference"
    if (
        re.search(
            r"\b(?:i|we)\s+(?:must|need\s+to|require|insist|only\s+use|"
            r"do\s+not\s+allow|don.t\s+allow)\b",
            lowered,
        )
        or re.search(
            r"\b(?:my|our)\s+(?:constraint|requirement|rule)\s+(?:is|requires?)\b",
            lowered,
        )
        or re.search(
            r"\b(?:you|the\s+assistant|nanobot)\s+(?:must|must\s+not|may\s+not|"
            r"should\s+always|should\s+never)\b",
            lowered,
        )
        or re.match(r"^\s*(?:always|never|do\s+not|don.t)\s+(?!mind\b)", lowered)
    ):
        return "constraint"
    explicit_person_identity = bool(
        re.search(r"(?i)\b(?:my\s+name\s+is|i\s+am\s+(?:called|named))\b", assertion)
        or re.search(
            r"(?i)\bmy\s+(?:wife|husband|partner|spouse)\s+is\s+"
            r"(?:called\s+|named\s+)[a-z][a-z'_-]{1,40}\b",
            assertion,
        )
        or re.search(
            r"\b[Mm]y\s+(?:wife|husband|partner|spouse)\s+is\s+"
            r"(?:(?:actually|currently|now)\s+)?"
            r"[A-Z][A-Za-z'_-]{1,40}\b",
            assertion,
        )
        or re.search(
            r"(?i)\b(?:my\s+(?:job|role|title|time\s*zone|timezone)\s+is|"
            r"i\s+work\s+as|i\s+(?:actually\s+|currently\s+|now\s+)?"
            r"(?:live|reside)\s+in)\b",
            assertion,
        )
    )
    if explicit_person_identity:
        return "person"
    if re.search(
        r"\b(?:(?:i|we)\s+(?:have\s+)?decided|we\s+agreed|"
        r"(?:my|our)\s+decision\s+is)\b",
        lowered,
    ):
        return "decision"
    transient_commitment = bool(
        re.search(
            r"\b(?:in\s+(?:\d+|a|an|one|two|three|four|five|few)\s+"
            r"(?:seconds?|minutes?|hours?)|right\s+now|shortly|soon|today|tonight|"
            r"this\s+(?:answer|chat|message|session|turn))\b",
            lowered,
        )
    )
    generic_execution_ack = bool(
        re.fullmatch(
            r"\s*(?:i|we)\s+will\s+(?:try\s+(?:it|this|that)|"
            r"check\s+(?:it|this|that)|do\s+(?:it|this|that)|continue|proceed|"
            r"restart|take\s+a\s+look|look\s+into\s+it|"
            r"(?:fix|update|check|test|run|restart|send|open)\s+"
            r"(?:(?:it|this|that)|(?:the\s+)?(?:file|email|server|task|thing|"
            r"command|code|app)))\s*[.!]?\s*",
            lowered,
        )
    )
    if not transient_commitment and not generic_execution_ack and re.search(
        r"\b(?:(?:i|we)\s+(?:will|plan\s+to)|(?:i\s+am|i.m|we\s+are|we.re)\s+"
        r"committed\s+to)\b",
        lowered,
    ):
        return "commitment"
    event_anchor = bool(
        re.search(
            r"\b(?:scheduled|cancell?ed|rescheduled|postponed|due|starts?|begins?|"
            r"today|tomorrow|tonight|monday|tuesday|wednesday|thursday|friday|"
            r"saturday|sunday|january|february|march|april|may|june|july|august|"
            r"september|october|november|december|next\s+(?:week|month|year))\b|"
            r"\b\d{1,4}(?:[-/]\d{1,2}){1,2}\b|"
            r"\b(?:at\s+)?\d{1,2}(?::\d{2})?\s*(?:a\.?m\.?|p\.?m\.?)\b",
            lowered,
        )
    )
    if event_anchor and (
        re.search(
            r"\b(?:my|our)\s+(?:[a-z][a-z0-9_'\-]*\s+){0,2}"
            r"(?:anniversary|appointment|birthday|consultation|deadline|due\s+date|"
            r"event|meeting|visit)\b(?:\s+(?:to|with)\s+(?:the\s+)?"
            r"[a-z][a-z0-9_'\-]*(?:\s+[a-z][a-z0-9_'\-]*){0,2})?\s+"
            r"(?:is|are|falls?|happens?|starts?|begins?|"
            r"will\s+be|scheduled\b)",
            lowered,
        )
        or re.search(
            r"\b(?:i|we)\s+(?:have|scheduled|am\s+attending|are\s+attending)\b"
            r".{0,60}\b(?:appointment|consultation|deadline|event|meeting|visit)\b",
            lowered,
        )
        or re.search(
            r"\b(?:appointment|consultation|deadline|due\s+date|event|meeting|visit)\b.{0,60}"
            r"\b(?:for\s+me|for\s+us|my|our)\b",
            lowered,
        )
        or re.search(
            r"\b(?:my|our)\s+(?:chemotherapy|procedure|radiation|radiotherapy|"
            r"surgery|treatment)\s+(?:(?:is\s+)?scheduled\s+(?:for|on)|"
            r"(?:(?:is|was|has\s+been)\s+)?(?:cancell?ed|postponed|rescheduled)"
            r"(?:\s+(?:for|to))?|is|starts?|begins?)\s+(?:on\s+)?(?:today|tomorrow|"
            r"monday|tuesday|wednesday|thursday|friday|saturday|sunday|"
            r"january|february|march|april|may|june|july|august|september|"
            r"october|november|december|\d{1,2}(?:/\d{1,2})?)\b|"
            r"\b(?:my|our)\s+(?:chemotherapy|procedure|radiation|radiotherapy|"
            r"surgery|treatment)\s+(?:(?:is|was|has\s+been)\s+)?"
            r"(?:cancell?ed|postponed|rescheduled)\b",
            lowered,
        )
    ):
        return "event"
    if re.search(
        r"\b(?:my|our)\s+(?:[a-z][a-z0-9_'\-]*\s+){0,2}"
        r"(?:anniversary|appointment|birthday|consultation|deadline|due\s+date|"
        r"event|meeting|visit)\b",
        lowered,
    ):
        # An event-shaped subject without a date/schedule anchor is ordinary
        # description, not a durable event and not a generic personal fact.
        return None
    owned_scope = bool(
        re.search(
            r"\b(?:my|our)\s+(?:(?:current|open|active)\s+)?"
            r"(?:project|repo|repository|workspace)\b",
            lowered,
        )
    )
    issue_term = bool(
        re.search(
            r"\b(?:bug|error|issue|broken|failing|failed|blocked|doesn.t work|unresolved)\b",
            lowered,
        )
    )
    first_person_issue = bool(
        re.search(
            r"\b(?:i|we)\s+(?:am|are|'m|'re|have|hit|"
            r"keep\s+getting|cannot|can.t)\b.{0,100}"
            r"\b(?:bug|error|issue|broken|failing|failed|blocked|doesn.t work|unresolved)\b",
            lowered,
        )
    )
    owned_scope_issue = owned_scope and issue_term and bool(
        re.search(
            r"\b(?:has|have|is|are|keeps?|remains?|still)\b.{0,100}"
            r"\b(?:bug|error|issue|broken|failing|failed|blocked|doesn.t work|unresolved)\b",
            lowered,
        )
    )
    historical_issue = bool(
        re.search(
            r"\b(?:yesterday|last\s+(?:week|month|year)|previously|formerly|"
            r"used\s+to|was|were)\b",
            lowered,
        )
    )
    if (
        (first_person_issue or owned_scope_issue)
        and not historical_issue
        and _is_current_issue_sentence(assertion)
    ):
        return "open_issue"
    project_state = bool(
        re.search(
            r"\b(?:my|our)\s+(?:(?:current|open|active)\s+)?"
            r"(?:project|repo|repository|workspace)\b",
            lowered,
        )
        or re.search(
            r"\b(?:i\s+am|i.m|we\s+are|we.re)\s+"
            r"(?:currently\s+)?(?:building|maintaining|working\s+on)\b",
            lowered,
        )
        or re.search(
            r"\b(?:i|we)\s+(?:own|maintain|work\s+on)\s+(?:the\s+)?"
            r"(?:project|repo|repository|workspace)\b",
            lowered,
        )
    )
    bare_working_on = bool(
        re.search(
            r"\b(?:i\s+am|we\s+are)\s+(?:currently\s+)?working\s+on\b",
            lowered,
        )
        and not re.search(r"\b(?:project|repo|repository|workspace)\b", lowered)
    )
    proper_work_target = bool(
        re.search(
            r"(?i:\b(?:i\s+am|we\s+are)\s+(?:currently\s+)?working\s+on\s+)"
            r"[A-Z][A-Za-z0-9_-]{1,40}\b",
            assertion,
        )
    )
    if project_state and (not bare_working_on or proper_work_target):
        return "project"
    if re.search(r"\bi\s+am\s+allergic\s+to\b", lowered):
        return "durable_fact"
    if re.search(
        r"\bi\s+(?:(?:was|have\s+been)\s+diagnosed\s+with|"
        r"am\s+(?:currently\s+)?undergoing|had\s+(?:a\s+)?stroke(?!\s+of\b))\b",
        lowered,
    ):
        return "durable_fact"
    if re.search(
        r"\bi\s+(?:take|am\s+taking|am\s+(?:currently\s+)?on|"
        r"am\s+not\s+(?:taking|on)|am\s+no\s+longer\s+on|"
        r"no\s+longer\s+take|stopped\s+taking)\b",
        lowered,
    ) and _KNOWN_MEDICATION_RE.search(lowered):
        return "durable_fact"
    if re.search(
        rf"\bi\s+(?:do\s+not|don.t|no\s+longer)\s+have\b.{{0,60}}"
        rf"\b(?:{_KNOWN_CONDITION_PATTERN})\b",
        lowered,
    ):
        return "durable_fact"
    if re.search(
        r"\bi\s+(?:do\s+not|don.t|no\s+longer)\s+have\s+"
        r"(?:(?:a|an|the)\s+)?[a-z][a-z0-9'_-]*"
        r"(?:\s+[a-z][a-z0-9'_-]*){0,4}\s+(?:disease|syndrome)\b",
        lowered,
    ):
        return "durable_fact"
    if re.search(
        rf"\b(?:i\s+(?:am\s+)?(?:{_KNOWN_CONDITION_PATTERN})-free|"
        rf"i\s+recovered\s+from\s+(?:{_KNOWN_CONDITION_PATTERN})|"
        rf"my\s+(?:{_KNOWN_CONDITION_PATTERN})\s+(?:got|became)\s+"
        r"(?:better|worse))\b",
        lowered,
    ):
        return "durable_fact"
    if re.search(r"\b(?:my .{1,40} (?:is|are)|i live|i work|i own|i use|i have)\b", lowered):
        return "durable_fact"
    return None


def _sentences(text: str) -> list[str]:
    assertion_text = _strip_nonassertion_blocks(text)
    return [
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+|\n+", assertion_text)
        if part.strip()
    ]


def _word_set(text: str) -> set[str]:
    return {word.lower() for word in re.findall(r"[A-Za-z0-9_-]{3,}", text)}


_MEMORY_TOPIC_ALIASES: dict[str, set[str]] = {
    "response": {"answer", "message", "reply", "report", "response", "status"},
    "length": {"brief", "concise", "detailed", "length", "long", "short", "verbose"},
    "spouse": {"husband", "partner", "spouse", "wife"},
    "project": {"project", "repo", "repository", "workspace"},
    "repo": {"project", "repo", "repository", "workspace"},
    "output": {
        "answer", "bullet", "json", "markdown", "message", "output", "reply",
        "report", "response", "result", "table", "yaml",
    },
    "format": {"bullet", "format", "json", "layout", "markdown", "table", "yaml"},
    "style": {"format", "language", "layout", "plain", "plain-language", "style", "tone"},
    "theme": {"appearance", "blue", "color", "colors", "dashboard", "dark", "light", "theme"},
    "name": {"called", "name", "named"},
    "timezone": {"eastern", "pacific", "time", "timezone", "zone"},
    "location": {"address", "city", "live", "location"},
    "language": {"english", "language", "spanish"},
    "security": {"encryption", "https", "security", "ssl", "tls"},
    "transport": {"https", "ssl", "tls", "transport"},
    "status": {"active", "blocked", "closed", "open", "status"},
    "error": {"broken", "error", "failure", "issue"},
    "owner": {"belongs", "own", "owner"},
    "role": {"job", "role", "title", "work"},
    "vehicle": {
        "bike", "bicycle", "car", "drive", "model", "motorcycle", "tesla",
        "truck", "vehicle",
    },
    "pet": {"cat", "dog", "pet"},
    "children": {"child", "children", "daughter", "kid", "son"},
    "employer": {"company", "employer", "job", "work"},
    "health": {
        "allergy", "allergic", "asthma", "blood", "cancer", "chemotherapy",
        "clinic", "condition", "diagnosis", "diabetes", "doctor", "health",
        "hospital", "medication", "prescription", "provider", "surgery",
        "treatment",
    },
    "condition": {
        "aids", "allergy", "anxiety", "arthritis", "asthma", "atrial", "autism",
        "bipolar", "cancer", "copd", "covid", "crohn", "depression", "diabetes",
        "disease", "epilepsy", "fibrillation", "hiv", "hypertension",
        "hypothyroidism", "illness", "infection", "kidney", "leukemia", "lupus",
        "lymphoma", "migraine", "multiple", "parkinson", "ptsd", "sclerosis",
        "stroke", "syndrome",
    },
    "allergy": {"allergic", "allergies", "allergy"},
    "diagnosis": {"condition", "diagnosis", "diagnosed"},
    "medication": {
        "drug", "inhaler", "medication", "on", "prescription", "take", "taking",
    },
    "treatment": {"dialysis", "therapy", "treatment", "undergoing"},
    "provider": {
        "cardiologist", "clinic", "clinician", "dentist", "doctor", "hospital",
        "nurse", "oncologist", "physician", "provider", "psychiatrist", "surgeon",
        "therapist",
    },
}
_MEMORY_KEY_QUALIFIERS = {
    "active", "context", "current", "default", "detail", "health", "identity", "info",
    "history", "preferred", "primary", "setting", "state", "status", "user", "value",
}


def _normalize_topic_token(token: str) -> str:
    token = token.lower()
    if token in {"status"}:
        return token
    if token.endswith("ies") and len(token) > 4:
        return f"{token[:-3]}y"
    if token.endswith("s") and not token.endswith("ss") and len(token) > 4:
        return token[:-1]
    return token


_NORMALIZED_MEMORY_TOPIC_ALIASES: dict[str, set[str]] = {
    _normalize_topic_token(topic): {
        _normalize_topic_token(alias) for alias in aliases
    }
    for topic, aliases in _MEMORY_TOPIC_ALIASES.items()
}


def _memory_key_matches_content(memory_key: str, content: str) -> bool:
    topic = memory_key.split(".", 1)[1] if "." in memory_key else ""
    components = [
        _normalize_topic_token(token)
        for token in re.findall(r"[A-Za-z0-9]+", topic.replace("_", "-"))
    ]
    components = [token for token in components if token not in _MEMORY_KEY_QUALIFIERS]
    if not components:
        return False
    raw_content_tokens = re.findall(r"[A-Za-z0-9][A-Za-z0-9-]*", content)
    content_tokens = {
        _normalize_topic_token(token)
        for raw_token in raw_content_tokens
        for token in (raw_token, *raw_token.split("-"))
        if token
    }

    def supported(component: str) -> bool:
        if component == "provider" and any(
            token.endswith("ologist") for token in content_tokens
        ):
            return True
        return bool(
            content_tokens.intersection(
                _NORMALIZED_MEMORY_TOPIC_ALIASES.get(component, {component})
            )
        )

    return all(
        supported(token) for token in components
    )


def canonical_memory_key(category: str, content: str) -> str | None:
    """Derive a conservative value-independent identity for mutable memory.

    Unknown mutable topics remain report-only. Reflect may select an evidence
    item, but it cannot invent a new upsert namespace from a changing value.
    """
    lowered = clean_text(content, 500).lower().replace("’", "'")
    lowered = re.sub(r"\bi'm\b", "i am", lowered)
    original = clean_text(content, 500)
    scope_kind: str | None = None
    scope_name: str | None = None
    for pattern in (
        r"\b(?:for|in|on)\s+(?:the\s+)?([a-z][a-z0-9_-]{1,40})\s+"
        r"(dashboard|project|repo|repository|workspace)\b",
        r"\b(?:for|in|on)\s+(?:the\s+)?"
        r"(dashboard|project|repo|repository|workspace)\s+"
        r"([a-z][a-z0-9_-]{1,40})\b",
    ):
        match = re.search(pattern, lowered)
        if not match:
            continue
        if match.group(1) in {"dashboard", "project", "repo", "repository", "workspace"}:
            raw_kind, raw_name = match.group(1), match.group(2)
        else:
            raw_name, raw_kind = match.group(1), match.group(2)
        if raw_name not in {"current", "my", "one", "our", "that", "this"}:
            scope_kind = "repo" if raw_kind == "repository" else raw_kind
            scope_name = slug(raw_name, 48)
            break
    if scope_kind is None and category in {"preference", "constraint"}:
        artifact = re.search(
            r"\b(?:for|in|on)\s+(?:all\s+|the\s+)?"
            r"(api\s+responses?|code\s+reviews?|config(?:uration)?\s+files?|"
            r"dashboards?|documents?|emails?|reports?)\b",
            lowered,
        )
        if artifact:
            scope_kind = "context"
            scope_name = slug(artifact.group(1).rstrip("s"), 48)
        elif category == "preference":
            themed_artifact = re.search(
                r"\b(?:dark|light)\s+(dashboards?|documents?|emails?|reports?)\b",
                lowered,
            )
            if themed_artifact:
                scope_kind = "context"
                scope_name = slug(themed_artifact.group(1).rstrip("s"), 48)
    if (
        scope_kind is None
        and category in {"preference", "constraint"}
        and re.search(r"\b(?:for|in|on)\s+(?:the\s+)?[a-z0-9]", lowered)
    ):
        # An explicit but unknown context must never collapse into a global
        # singleton preference/constraint document.
        return None

    def scoped_topic(topic: str) -> str:
        if scope_kind and scope_name:
            return f"{category}.{scope_kind}.{scope_name}.{topic}"
        return f"{category}.{topic}"
    if category == "person":
        spouse_identity = bool(
            re.search(
                r"(?i)\b(?:spouse|wife|husband|partner)\s+is\s+"
                r"(?:called\s+|named\s+)[a-z][a-z'_-]{1,40}\b",
                original,
            )
            or re.search(
                r"\b(?:spouse|wife|husband|partner)\s+is\s+"
                r"(?:(?:actually|currently|now)\s+)?"
                r"[A-Z][A-Za-z'_-]{1,40}\b",
                original,
            )
        )
        if spouse_identity:
            return "person.spouse.identity"
        if re.search(r"\b(?:my\s+name|name\s+is|called|named)\b", lowered):
            return "person.name"
        if re.search(
            r"\b(?:address|city|location|i\s+(?:actually\s+|currently\s+|now\s+)?"
            r"(?:live|reside)|lives?\s+in)\b",
            lowered,
        ):
            return "person.location"
        if re.search(r"\b(?:timezone|time\s+zone)\b", lowered):
            return "person.timezone"
        if re.search(r"\b(?:job|role|title|i\s+work|works?\s+as)\b", lowered):
            return "person.role"
        return None

    length_terms = bool(
        re.search(r"\b(?:brief|concise|detailed|length|long|short|verbose)\b", lowered)
    )
    if category in {"preference", "constraint"}:
        if length_terms and re.search(r"\bstatus\s+reports?\b", lowered):
            return scoped_topic("status_report_length")
        if length_terms and re.search(
            r"\b(?:answers?|messages?|repl(?:y|ies)|reports?|responses?)\b",
            lowered,
        ):
            return scoped_topic("response_length")
        if re.search(r"\b(?:bullet|format|json|markdown|table|yaml)\b", lowered):
            return scoped_topic("output_format")
        if re.search(r"\b(?:plain\s+language|style|tone)\b", lowered):
            return scoped_topic("style")
        if category == "preference" and re.search(
            r"\b(?:appearance|color|colours?|colors?|dashboard|dark|light|theme)\b",
            lowered,
        ):
            return scoped_topic("theme")
        if category == "preference" and re.search(
            r"\b(?:english|language|spanish)\b", lowered
        ):
            return scoped_topic("language")
        if category == "constraint" and re.search(
            r"\b(?:encryption|https|ssl|tls|transport\s+security)\b", lowered
        ):
            return scoped_topic("transport_security")
        return None

    project_stop = {
        "a", "active", "actually", "an", "blocked", "closed", "current",
        "currently", "definitely", "fixed", "has", "is", "my", "no", "not",
        "now", "open", "our", "resolved", "still", "the",
    }
    if category == "project" and re.search(
        r"\b(?:my|our)\s+(?:project|repo|repository|workspace)\s+is\s+"
        r"(?:not|no\s+longer)\b",
        lowered,
    ):
        return None
    project_patterns = (
        r"\b(?:project|repo|repository|workspace)\s+(?:is\s+)?"
        r"(?:named|called)\s+([a-z][a-z0-9_-]{1,40})\b",
        r"\b(?:project|repo|repository|workspace)\s+(?:is\s+)?"
        r"([a-z][a-z0-9_-]{1,40})\b",
        r"\b(?:building|maintaining|working\s+on)\s+(?:the\s+)?"
        r"(?:(?:project|repo|repository|workspace)\s+)?"
        r"([a-z][a-z0-9_-]{1,40})\b",
    )
    project_name: str | None = None
    for pattern in project_patterns:
        match = re.search(pattern, lowered)
        if match and match.group(1) not in project_stop:
            project_name = slug(match.group(1), 48)
            break

    if category == "project" and project_name:
        if re.search(
            r"\b(?:project|repo|repository|workspace)\s+(?:is\s+)?"
            r"(?:named|called)\b",
            lowered,
        ) or re.search(
            r"\b(?:my|our)\s+(?:project|repo|repository|workspace)\s+is\s+"
            r"[a-z][a-z0-9_-]{1,40}\b",
            lowered,
        ):
            return f"project.{project_name}.identity"
        if re.search(
            r"\b(?:active|blocked|building|closed|current|maintaining|open|paused|"
            r"working\s+on)\b",
            lowered,
        ):
            return f"project.{project_name}.status"
        return None

    if category == "open_issue":
        if re.search(
            r"\b(?:yesterday|last\s+(?:week|month|year)|previously|formerly|"
            r"used\s+to|was|were)\b",
            lowered,
        ):
            return None
        if not re.search(
            r"\b(?:bug|error|failure|issue|blocked|broken|failing|unresolved|"
            r"cannot|can.t|keep\s+getting)\b",
            lowered,
        ):
            return None
        issue_stop = {
            "a", "affecting", "am", "an", "and", "are", "blocked", "broken",
            "bug", "can", "cannot", "cant", "current", "error", "failure", "failing",
            "fix", "for", "get", "getting", "has", "have", "i", "in", "is", "issue", "keep",
            "keeps", "my", "on", "open", "our", "project", "recurring", "remains",
            "repo", "repository", "stated", "still", "the", "unresolved", "user",
            "we", "with", "work", "workspace", "need",
        }
        issue_topics = [
            token.lower()
            for token in re.findall(r"[a-z][a-z0-9_-]{2,40}", lowered)
            if token.lower() not in issue_stop
        ]
        issue_topics = list(dict.fromkeys(issue_topics))[:4]
        if issue_topics:
            return f"open_issue.{'.'.join(slug(part, 32) for part in issue_topics)}.status"

    if category == "durable_fact":
        def health_identity(value: str) -> str:
            corrected = re.sub(
                r"(?i)^\s*(?:not|no\s+longer|never)\s+",
                "",
                value,
            ).strip(" .!?,")
            return slug(corrected, 60) if corrected else ""

        diagnosis = re.search(
            r"\bmy\s+diagnosis\s+is\s+"
            r"(?:(?:actually|currently|now)\s+)?(?:(?:a|an|the)\s+)?"
            r"([a-z0-9][a-z0-9 _-]{1,60})\s*[.!]?$",
            lowered,
        )
        if diagnosis:
            identity = health_identity(diagnosis.group(1))
            return f"durable_fact.health.diagnosis.{identity}" if identity else None
        diagnosed_with = re.search(
            r"\bi\s+(?:was|have\s+been)\s+diagnosed\s+with\s+"
            r"(?:(?:a|an|the)\s+)?"
            r"([a-z0-9][a-z0-9 _-]{1,60})\s*[.!]?$",
            lowered,
        )
        if diagnosed_with:
            identity = health_identity(diagnosed_with.group(1))
            return f"durable_fact.health.diagnosis.{identity}" if identity else None
        medication = re.search(
            r"\bmy\s+(?:medication|prescription)\s+is\s+"
            r"([a-z0-9][a-z0-9 _-]{1,60})\s*[.!]?$",
            lowered,
        )
        medication_identity: str | None = (
            medication.group(1) if medication else None
        )
        if medication:
            explicit_matches = list(
                _KNOWN_MEDICATION_RE.finditer(medication.group(1))
            )
            if len(explicit_matches) == 1:
                medication_identity = explicit_matches[0].group(0)
            elif len(explicit_matches) > 1:
                return None
        if not medication:
            medication = re.search(
                r"\bi\s+(?:take|am\s+taking|am\s+not\s+taking|"
                r"no\s+longer\s+take|stopped\s+taking)\s+"
                r"([a-z0-9][a-z0-9 _-]{1,60})\s*[.!]?$",
                lowered,
            )
            known_medications = (
                list(_KNOWN_MEDICATION_RE.finditer(medication.group(1)))
                if medication
                else []
            )
            if medication and len(known_medications) == 1:
                medication_identity = known_medications[0].group(0)
            elif medication:
                medication = None
                medication_identity = None
        if medication and medication_identity:
            identity = health_identity(medication_identity)
            return f"durable_fact.health.medication.{identity}" if identity else None
        medication_on = re.search(
            r"\bi\s+am\s+(?:(?:currently\s+)?on|not\s+on|"
            r"no\s+longer\s+on)\s+"
            r"([a-z0-9][a-z0-9 _-]{1,60})\s*[.!]?$",
            lowered,
        )
        medication_on_matches = (
            list(_KNOWN_MEDICATION_RE.finditer(medication_on.group(1)))
            if medication_on
            else []
        )
        if medication_on and len(medication_on_matches) == 1:
            identity = health_identity(medication_on_matches[0].group(0))
            return f"durable_fact.health.medication.{identity}" if identity else None
        allergy = re.search(
            r"\b(?:my\s+allerg(?:y|ies)\s+(?:is|are)|i\s+am\s+allergic\s+to)\s+"
            r"([a-z0-9][a-z0-9 _-]{1,60})\s*[.!]?$",
            lowered,
        )
        if allergy:
            allergen = re.split(
                r"(?i)\s+(?:because|since|with)\b", allergy.group(1), maxsplit=1
            )[0]
            if re.search(r"(?i)(?:,|\band\b|\bor\b)", allergen):
                return None
            identity = health_identity(allergen)
            return f"durable_fact.health.allergy.{identity}" if identity else None
        provider = re.search(
            r"\bmy\s+(doctor|clinician|dentist|nurse|physician|psychiatrist|surgeon|"
            r"therapist|[a-z]{2,}ologist)\s+is\b",
            lowered,
        )
        if provider:
            return f"durable_fact.health.provider.{slug(provider.group(1), 48)}"
        condition_names = _KNOWN_CONDITION_PATTERN
        condition_medication = re.search(
            rf"\bmy\s+({condition_names})\s+"
            r"(?:inhaler|medication|prescription)\s+is\b",
            lowered,
        )
        if condition_medication:
            return (
                "durable_fact.health.condition."
                f"{slug(condition_medication.group(1), 48)}.medication.primary"
            )
        condition_provider = re.search(
            rf"\bmy\s+({condition_names})\s+"
            r"(doctor|clinician|dentist|nurse|physician|psychiatrist|surgeon|"
            r"therapist|[a-z]{2,}ologist)\s+is\b",
            lowered,
        )
        if condition_provider:
            return (
                "durable_fact.health.condition."
                f"{slug(condition_provider.group(1), 48)}.provider."
                f"{slug(condition_provider.group(2), 48)}"
            )
        condition_treatment = re.search(
            rf"\bmy\s+({condition_names})\s+treatment\s+is\b",
            lowered,
        )
        if condition_treatment:
            return (
                "durable_fact.health.condition."
                f"{slug(condition_treatment.group(1), 48)}.treatment.primary"
            )
        condition_status = re.search(
            rf"\b(?:my\s+({condition_names})\s+(?:has|is|remains)\b|"
            rf"i\s+have\s+({condition_names})\b|"
            rf"i\s+(?:do\s+not|don.t|no\s+longer)\s+have\s+({condition_names})\b)",
            lowered,
        )
        if condition_status:
            condition = (
                condition_status.group(1)
                or condition_status.group(2)
                or condition_status.group(3)
            )
            return (
                "durable_fact.health.condition."
                f"{slug(condition, 48)}.status"
            )
        named_condition = (
            r"[a-z][a-z0-9'_-]*(?:\s+[a-z][a-z0-9'_-]*){0,4}\s+"
            r"(?:disease|syndrome)"
        )
        generic_condition_status = re.search(
            rf"\b(?:my\s+({named_condition})\s+(?:has|is|remains)\b|"
            rf"i\s+have\s+(?:(?:a|an|the)\s+)?({named_condition})\b|"
            rf"i\s+(?:do\s+not|don.t|no\s+longer)\s+have\s+"
            rf"(?:(?:a|an|the)\s+)?({named_condition})\b)",
            lowered,
        )
        if generic_condition_status:
            condition = next(
                group for group in generic_condition_status.groups() if group
            )
            return (
                "durable_fact.health.condition."
                f"{slug(condition, 48)}.status"
            )
        condition_change = re.search(
            rf"\b(?:i\s+(?:am\s+)?({condition_names})-free\b|"
            rf"i\s+recovered\s+from\s+({condition_names})\b|"
            rf"my\s+({condition_names})\s+(?:got|became)\s+"
            r"(?:better|worse)\b)",
            lowered,
        )
        if condition_change:
            condition = next(
                group for group in condition_change.groups() if group
            )
            return (
                "durable_fact.health.condition."
                f"{slug(condition, 48)}.status"
            )
        dialysis = re.search(r"\bi\s+am\s+(?:currently\s+)?undergoing\s+dialysis\b", lowered)
        if dialysis:
            return "durable_fact.health.treatment.dialysis.status"
        stroke_history = re.search(
            r"\bi\s+had\s+(?:a\s+)?stroke\b(?!\s+of\b)", lowered
        )
        if stroke_history:
            return "durable_fact.health.condition.stroke.history"
        if re.search(r"\bblood\s+pressure\b", lowered):
            return "durable_fact.health.blood_pressure"
        primary_vehicle = re.search(
            r"\b(?:my|our)\s+(?:current|main|primary)\s+"
            r"(bike|bicycle|car|motorcycle|truck|vehicle)\s+(?:is|are)\b",
            lowered,
        )
        if primary_vehicle:
            return "durable_fact.primary_vehicle"
        if re.search(r"\b(?:i|we)\s+(?:live|reside)\s+in\b", lowered):
            return "durable_fact.location"
        employer = re.search(
            r"\b(?:i|we)\s+work\s+(?:at|for)\s+(?:the\s+)?"
            r"([a-z][a-z0-9_-]{1,40})\b",
            lowered,
        )
        if employer:
            return f"durable_fact.employer.{slug(employer.group(1), 48)}"
        vehicle_model = re.search(
            r"\b(?:i|we)\s+(?:drive|have|own|use)\s+(?:a|an|the)?\s*"
            r"(tesla\s+model\s+[a-z0-9-]+)\b",
            lowered,
        )
        if vehicle_model:
            return f"durable_fact.vehicle.{slug(vehicle_model.group(1), 48)}"
        vehicle_named = re.search(
            r"\b(?:i|we)\s+(?:drive|have|own|use)\s+(?:a|an|the)?\s*"
            r"(bike|bicycle|car|motorcycle|truck|vehicle)\s+"
            r"(?:called|named)\s+([a-z][a-z0-9_-]{1,40})\b",
            lowered,
        )
        if vehicle_named:
            return (
                f"durable_fact.vehicle.{slug(vehicle_named.group(1), 24)}."
                f"{slug(vehicle_named.group(2), 40)}"
            )
        vehicle_generic = re.search(
            r"\b(?:i|we)\s+(?:drive|have|own|use)\s+(?:a|an|one|the)?\s*"
            r"(bike|bicycle|car|motorcycle|truck|vehicle)s?\s*[.!]?$",
            lowered,
        )
        if vehicle_generic:
            return f"durable_fact.vehicle.{slug(vehicle_generic.group(1), 48)}"
        pet_named = re.search(
            r"\b(?:i|we)\s+(?:have|own)\s+(?:a|an|the)?\s*"
            r"(cat|dog|pet)\s+(?:called|named)\s+"
            r"([a-z][a-z0-9_-]{1,40})\b",
            lowered,
        )
        if pet_named:
            return (
                f"durable_fact.pet.{slug(pet_named.group(1), 24)}."
                f"{slug(pet_named.group(2), 40)}"
            )
        pet_generic = re.search(
            r"\b(?:i|we)\s+(?:have|own)\s+(?:a|an|one|the)?\s*"
            r"(cat|dog|pet)s?\s*[.!]?$",
            lowered,
        )
        if pet_generic:
            return f"durable_fact.pet.{slug(pet_generic.group(1), 48)}"
        child_named = re.search(
            r"\b(?:i|we)\s+have\s+(?:a|an|the)?\s*"
            r"(child|daughter|kid|son)\s+(?:called|named)\s+"
            r"([a-z][a-z0-9_-]{1,40})\b",
            lowered,
        )
        if not child_named:
            child_named = re.search(
                r"\bmy\s+(child|daughter|kid|son)\s+is\s+"
                r"(?:called\s+|named\s+)([a-z][a-z0-9_-]{1,40})\b",
                lowered,
            )
        if not child_named:
            child_named = re.search(
                r"\b[Mm]y\s+(child|daughter|kid|son)\s+is\s+"
                r"([A-Z][A-Za-z0-9_-]{1,40})\b",
                original,
            )
        if child_named:
            return (
                f"durable_fact.children.{slug(child_named.group(1), 24)}."
                f"{slug(child_named.group(2), 40)}"
            )
        child_generic = re.search(
            r"\b(?:i|we)\s+have\s+(?:a|an|one|the)?\s*"
            r"(child|children|daughter|kid|son)s?\s*[.!]?$",
            lowered,
        )
        if child_generic:
            return f"durable_fact.children.{slug(child_generic.group(1), 48)}"
    return None


def verified_issue_memory_key(exchange: Exchange) -> str | None:
    """Return the open-issue document targeted by a verified resolution."""
    resolution = exchange.verified_resolution_sentence
    if not resolution:
        return None
    resolution_topics = _resolution_topic_tokens(resolution)
    ranked: list[tuple[int, str]] = []
    for sentence in _sentences(exchange.user_text):
        if not _is_current_issue_sentence(sentence):
            continue
        key = canonical_memory_key("open_issue", f"User stated: {sentence}")
        if not key:
            continue
        overlap = len(resolution_topics.intersection(_resolution_topic_tokens(sentence)))
        if overlap:
            ranked.append((overlap, key))
    if not ranked:
        return None
    best_overlap = max(overlap for overlap, _ in ranked)
    best_keys = {
        key for overlap, key in ranked if overlap == best_overlap
    }
    return next(iter(best_keys)) if len(best_keys) == 1 else None


def closest_source_sentence(source: str, fact: str) -> str:
    fact_words = _word_set(fact)
    choices = _sentences(source)
    if not choices:
        return clean_text(source, 500)
    return max(
        choices,
        key=lambda sentence: len(fact_words & _word_set(sentence)) / max(1, len(fact_words | _word_set(sentence))),
    )


def coalesce_exchange_candidates(
    candidates: Sequence[Candidate],
    exchange: Exchange,
) -> tuple[list[Candidate], list[Candidate]]:
    """Choose the last exact user assertion for each category in one exchange."""
    sentences = _sentences(exchange.user_text)
    positions = {
        f"User stated: {clean_text(sentence, 250)}": index
        for index, sentence in enumerate(sentences)
    }
    winners: dict[str, tuple[int, Candidate]] = {}
    for candidate in candidates:
        position = (
            len(sentences)
            if candidate.category == "resolved_error"
            else positions.get(candidate.content, -1)
        )
        slot = (
            f"mutable:{candidate.memory_key}"
            if candidate.category in MUTABLE_CATEGORIES and candidate.memory_key
            else f"candidate:{candidate.candidate_id}"
        )
        current = winners.get(slot)
        if current is None or (position, candidate.candidate_id) > (
            current[0],
            current[1].candidate_id,
        ):
            winners[slot] = (position, candidate)
    winner_ids = {candidate.candidate_id for _, candidate in winners.values()}
    kept = [
        candidate
        for _, candidate in sorted(
            winners.values(), key=lambda item: (item[0], item[1].category)
        )
    ]
    superseded = [
        candidate for candidate in candidates if candidate.candidate_id not in winner_ids
    ]
    return kept, superseded


def candidates_from_facts(
    exchange: Exchange,
    facts: Sequence[dict[str, Any]],
    *,
    source: str,
) -> list[Candidate]:
    if memory_opt_out(exchange.user_text) or has_transformed_content_framing(
        exchange.user_text
    ):
        return []
    candidates: list[Candidate] = []
    seen: set[str] = set()
    for fact in facts:
        text = clean_text(fact.get("text") or fact.get("content") or fact.get("fact"), 280)
        if not text or contains_secret(text) or contains_raw_error(text):
            continue
        if source == "user":
            sentence = closest_source_sentence(exchange.user_text, text)
            if sentence.endswith("?") or _QUESTION_RE.search(sentence):
                continue
            category = direct_user_category(sentence)
            if not category:
                continue
            if category == "open_issue" and exchange.verified_resolution:
                continue
            content = f"User stated: {clean_text(sentence, 250)}"
            candidate = Candidate.build(
                exchange=exchange,
                category=category,
                content=content,
                memory_key=canonical_memory_key(category, content),
                confidence=0.84,
                verified=True,
            )
        elif (
            source == "assistant"
            and exchange.verified_resolution_sentence
            and _is_affirmative_resolution_sentence(text)
        ):
            content = (
                "Verified resolution: "
                f"{clean_text(exchange.verified_resolution_sentence, 245)}"
            )
            candidate = Candidate.build(
                exchange=exchange,
                category="resolved_error",
                content=content,
                confidence=0.82,
                verified=True,
            )
        else:
            continue
        if candidate.content.lower() in seen:
            continue
        seen.add(candidate.content.lower())
        candidates.append(candidate)
        if len(candidates) == 12:
            break
    return coalesce_exchange_candidates(candidates, exchange)[0][:3]


def fallback_candidates(exchange: Exchange) -> list[Candidate]:
    """Conservative extraction used only when Hindsight dry-run is unavailable."""
    if memory_opt_out(exchange.user_text) or has_transformed_content_framing(
        exchange.user_text
    ):
        return []
    candidates: list[Candidate] = []
    for sentence in _sentences(exchange.user_text):
        if sentence.endswith("?") or _QUESTION_RE.search(sentence):
            continue
        if contains_secret(sentence) or is_nonassertive_memory_statement(sentence):
            continue
        category = direct_user_category(sentence)
        if not category:
            continue
        if category == "open_issue" and exchange.verified_resolution:
            continue
        content = f"User stated: {clean_text(sentence, 250)}"
        candidates.append(
            Candidate.build(
                exchange=exchange,
                category=category,
                content=content,
                memory_key=canonical_memory_key(category, content),
                confidence=0.80,
                verified=True,
            )
        )
        if len(candidates) == 12:
            break
    candidates, _ = coalesce_exchange_candidates(candidates, exchange)
    candidates = candidates[:3]
    if exchange.verified_resolution_sentence and len(candidates) < 3:
        resolution = exchange.verified_resolution_sentence
        if resolution:
            candidates.append(
                Candidate.build(
                    exchange=exchange,
                    category="resolved_error",
                    content=f"Verified resolution: {clean_text(resolution, 245)}",
                    confidence=0.80,
                    verified=True,
                )
            )
    return candidates


def latest_candidate_for_memory_key(
    exchange: Exchange,
    category: str,
    memory_key: str,
) -> Candidate | None:
    """Ground a selected mutable slot to its last exact assertion in the turn."""
    supported: list[Candidate] = []
    for sentence in _sentences(exchange.user_text):
        if sentence.endswith("?") or _QUESTION_RE.search(sentence):
            continue
        if contains_secret(sentence) or is_nonassertive_memory_statement(sentence):
            continue
        if direct_user_category(sentence) != category:
            continue
        content = f"User stated: {clean_text(sentence, 250)}"
        if canonical_memory_key(category, content) != memory_key:
            continue
        supported.append(
            Candidate.build(
                exchange=exchange,
                category=category,
                content=content,
                memory_key=memory_key,
                confidence=0.84,
                verified=True,
            )
        )
    if not supported:
        return None
    kept, _ = coalesce_exchange_candidates(supported, exchange)
    matching = [item for item in kept if item.memory_key == memory_key]
    return matching[-1] if matching else None


def tool_status(content: str) -> str:
    # Remove explicit zero-failure summaries before applying conservative
    # negative-term precedence ("0 failed, 3 passed" is a real success).
    negative_view = re.sub(
        r"(?i)\b(?:0\s+(?:failed|failures?|errors?)|no\s+(?:failures?|errors?))\b",
        "",
        content,
    )
    if any(
        pattern.search(negative_view) for pattern in _TOOL_NEGATIVE_SUCCESS_PATTERNS
    ):
        return "error"
    if any(pattern.search(content) for pattern in _TOOL_FAILURE_SUMMARY_PATTERNS):
        return "error"
    exit_codes = [int(match.group(1)) for match in _EXIT_STATUS_RE.finditer(content)]
    if exit_codes:
        return "success" if exit_codes[-1] == 0 else "error"
    if any(
        pattern.search(negative_view) for pattern in _TOOL_CONTEXTUAL_FAILURE_PATTERNS
    ):
        return "error"
    if any(pattern.search(content) for pattern in _TOOL_ERROR_PATTERNS):
        return "error"
    if any(pattern.search(content) for pattern in _TOOL_SUCCESS_PATTERNS):
        return "success"
    return "unknown"


def _skill_refs(arguments: str) -> list[str]:
    refs: set[str] = set()
    for match in _SKILL_PATH_RE.finditer(arguments.replace("\\\\", "/")):
        path = match.group("path").lstrip("/\\").replace("\\", "/")
        refs.add(path)
    return sorted(refs)


def extract_exchanges(session_key: str, messages: Sequence[dict[str, Any]]) -> list[Exchange]:
    """Convert public Nanobot messages into content-addressed completed exchanges."""
    groups: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    for raw in messages:
        if not isinstance(raw, dict):
            continue
        role = raw.get("role")
        if role == "system":
            continue
        if role == "user":
            if current:
                groups.append(current)
            current = [raw]
        elif current and role in {"assistant", "tool"}:
            current.append(raw)
    if current:
        groups.append(current)

    exchanges: list[Exchange] = []
    for group in groups:
        user = group[0]
        user_text = redact_secrets(clean_text(user.get("content"), 4_000), 4_000)
        if not user_text or NIGHTLY_MARKER in user_text:
            continue

        calls: dict[str, ToolEvent] = {}
        ordered_events: list[ToolEvent] = []
        final_text = ""
        sequence = 0
        for message in group[1:]:
            role = message.get("role")
            if role == "assistant":
                content = redact_secrets(clean_text(message.get("content"), 4_000), 4_000)
                tool_calls = message.get("tool_calls") or []
                if content and not tool_calls:
                    final_text = content
                for call in tool_calls:
                    if not isinstance(call, dict):
                        continue
                    function = call.get("function") if isinstance(call.get("function"), dict) else {}
                    call_id = str(call.get("id") or f"call-{sequence}")
                    name = str(function.get("name") or call.get("name") or "unknown")
                    arguments = function.get("arguments") or call.get("arguments") or ""
                    if not isinstance(arguments, str):
                        arguments = canonical_json(arguments)
                    redacted_arguments = redact_tool_arguments(arguments)
                    event = ToolEvent(
                        sequence=sequence,
                        tool_name=name,
                        call_id=call_id,
                        status="unknown",
                        args_fingerprint=stable_hash(redacted_arguments),
                        skill_refs=_skill_refs(arguments),
                    )
                    sequence += 1
                    calls[call_id] = event
                    ordered_events.append(event)
            elif role == "tool":
                call_id = str(message.get("tool_call_id") or f"result-{sequence}")
                content = redact_secrets(clean_text(message.get("content"), 600), 600)
                event = calls.get(call_id)
                if event is None:
                    event = ToolEvent(
                        sequence=sequence,
                        tool_name=str(message.get("name") or "unknown"),
                        call_id=call_id,
                        status="unknown",
                        args_fingerprint=stable_hash(""),
                    )
                    sequence += 1
                    ordered_events.append(event)
                event.status = tool_status(content)
                event.excerpt = content[:500]
                event.skill_refs = sorted(
                    set(event.skill_refs).union(_skill_refs(content))
                )

        if not final_text and not ordered_events:
            continue
        # Mutable-memory chronology follows when the user made the assertion,
        # not how long that agent turn happened to take.  Otherwise an older
        # slow turn can overwrite a later correction from another session.
        observed_at = str(user.get("timestamp") or "unset")
        payload = {
            "session_key": session_key,
            "user_timestamp": user.get("timestamp"),
            "observed_at": observed_at,
            "user_text": user_text,
            "assistant_final": final_text,
            "tools": [asdict(event) for event in ordered_events],
        }
        evidence_id = stable_hash(payload)
        exchanges.append(
            Exchange(
                evidence_id=evidence_id,
                session_key=session_key,
                observed_at=observed_at,
                user_text=user_text,
                assistant_final=final_text,
                tool_events=ordered_events,
            )
        )
    return exchanges


class Ledger:
    """SQLite checkpoint store; every method is idempotent and transaction-bound."""

    def __init__(self, path: Path, scope_fingerprint: str | None = None) -> None:
        self.path = path
        self.scope_fingerprint = clean_text(scope_fingerprint, 128) or None
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        if self.path.exists():
            metadata = self.path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ValueError("ledger path must be a regular, non-symlink file")
        else:
            try:
                descriptor = os.open(
                    self.path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
        self._lock = threading.RLock()
        self._initialize()

    def _secure_files(self) -> None:
        for candidate in (
            self.path,
            Path(f"{self.path}-wal"),
            Path(f"{self.path}-shm"),
        ):
            try:
                metadata = candidate.lstat()
                if stat.S_ISREG(metadata.st_mode):
                    os.chmod(candidate, 0o600)
            except OSError:
                continue

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        for attempt in range(6):
            try:
                journal_mode = str(
                    connection.execute("PRAGMA journal_mode").fetchone()[0]
                ).lower()
                if journal_mode != "wal":
                    connection.execute("PRAGMA journal_mode=WAL")
                break
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() or attempt == 5:
                    connection.close()
                    raise
                time.sleep(0.02 * (2**attempt))
        connection.execute("PRAGMA foreign_keys=ON")
        self._secure_files()
        return connection

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()
            self._secure_files()

    @staticmethod
    def _ensure_column(
        db: sqlite3.Connection,
        table: str,
        column: str,
        definition: str,
    ) -> None:
        existing = {
            str(row["name"])
            for row in db.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in existing:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _initialize(self) -> None:
        with self._lock:
            db = self._connect()
            try:
                db.executescript(
                    """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS exchanges (
                    evidence_id TEXT PRIMARY KEY,
                    session_key TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    user_text TEXT NOT NULL,
                    assistant_final TEXT NOT NULL,
                    tool_events_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    coverage TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    error TEXT NOT NULL DEFAULT '',
                    lease_owner TEXT,
                    lease_until TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at TEXT,
                    reviewed_run TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS candidates (
                    candidate_id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL REFERENCES exchanges(evidence_id),
                    category TEXT NOT NULL,
                    content TEXT NOT NULL,
                    memory_key TEXT,
                    confidence REAL NOT NULL,
                    verified INTEGER NOT NULL,
                    sensitivity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    operation_id TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    evidence_ids_json TEXT NOT NULL,
                    bundle_path TEXT NOT NULL DEFAULT '',
                    report_path TEXT,
                    status TEXT NOT NULL,
                    claim_id TEXT,
                    error TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS memory_keys (
                    memory_key TEXT PRIMARY KEY,
                    document_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    anchor_text TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    latest_observed_at TEXT,
                    latest_candidate_id TEXT,
                    write_owner TEXT,
                    write_lease_until TEXT,
                    write_observed_at TEXT,
                    write_candidate_id TEXT
                );
                CREATE TABLE IF NOT EXISTS seen_evidence (
                    evidence_id TEXT PRIMARY KEY,
                    observed_at TEXT NOT NULL,
                    seen_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ledger_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS private_findings (
                    finding_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
                )
                user_version = int(db.execute("PRAGMA user_version").fetchone()[0])
                if user_version > SCHEMA_VERSION:
                    raise RuntimeError(
                        f"ledger schema {user_version} is newer than supported {SCHEMA_VERSION}"
                    )
                self._ensure_column(db, "exchanges", "lease_owner", "TEXT")
                self._ensure_column(db, "exchanges", "lease_until", "TEXT")
                self._ensure_column(
                    db, "exchanges", "attempts", "INTEGER NOT NULL DEFAULT 0"
                )
                self._ensure_column(db, "exchanges", "next_attempt_at", "TEXT")
                self._ensure_column(db, "runs", "error", "TEXT NOT NULL DEFAULT ''")
                self._ensure_column(db, "runs", "completed_at", "TEXT")
                self._ensure_column(db, "runs", "claim_id", "TEXT")
                self._ensure_column(db, "memory_keys", "document_id", "TEXT")
                self._ensure_column(db, "memory_keys", "latest_observed_at", "TEXT")
                self._ensure_column(db, "memory_keys", "latest_candidate_id", "TEXT")
                self._ensure_column(db, "memory_keys", "write_owner", "TEXT")
                self._ensure_column(db, "memory_keys", "write_lease_until", "TEXT")
                self._ensure_column(db, "memory_keys", "write_observed_at", "TEXT")
                self._ensure_column(db, "memory_keys", "write_candidate_id", "TEXT")
                for key_row in db.execute(
                    "SELECT memory_key FROM memory_keys "
                    "WHERE latest_observed_at IS NULL OR latest_observed_at = ''"
                ).fetchall():
                    retained_rows = db.execute(
                        "SELECT e.observed_at, c.candidate_id FROM candidates AS c "
                        "JOIN exchanges AS e ON e.evidence_id = c.evidence_id "
                        "WHERE c.memory_key = ? AND c.status = 'retained'",
                        (key_row["memory_key"],),
                    ).fetchall()
                    if retained_rows:
                        retained = max(
                            retained_rows,
                            key=lambda row: observation_order(
                                str(row["observed_at"]),
                                str(row["candidate_id"]),
                            ),
                        )
                        observed, retained_id = observation_order(
                            str(retained["observed_at"]),
                            str(retained["candidate_id"]),
                        )
                        db.execute(
                            "UPDATE memory_keys SET latest_observed_at = ?, "
                            "latest_candidate_id = ? WHERE memory_key = ?",
                            (observed, retained_id, key_row["memory_key"]),
                        )
                # Raw candidate values are not needed to preserve canonical-key
                # ownership.  Clear legacy anchors so pruned health/person facts
                # do not remain indefinitely in otherwise bounded private state.
                db.execute("UPDATE memory_keys SET anchor_text = '' WHERE anchor_text != ''")
                for row in db.execute(
                    "SELECT memory_key FROM memory_keys "
                    "WHERE document_id IS NULL OR document_id = ''"
                ).fetchall():
                    db.execute(
                        "UPDATE memory_keys SET document_id = ? WHERE memory_key = ?",
                        (memory_document_id(str(row["memory_key"])), row["memory_key"]),
                    )
                db.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS memory_keys_document_id "
                    "ON memory_keys(document_id)"
                )
                db.execute(
                    "CREATE INDEX IF NOT EXISTS exchanges_work_queue "
                    "ON exchanges(status, next_attempt_at, observed_at)"
                )
                db.execute(
                    "CREATE INDEX IF NOT EXISTS seen_evidence_seen_at "
                    "ON seen_evidence(seen_at)"
                )
                db.execute(
                    "CREATE INDEX IF NOT EXISTS private_findings_created_at "
                    "ON private_findings(created_at)"
                )
                db.execute(
                    "INSERT OR IGNORE INTO seen_evidence "
                    "(evidence_id, observed_at, seen_at) "
                    "SELECT evidence_id, observed_at, created_at FROM exchanges"
                )
                self._prune_seen_evidence(db)
                if self.scope_fingerprint:
                    scope_row = db.execute(
                        "SELECT value FROM ledger_meta WHERE key = 'scope_fingerprint'"
                    ).fetchone()
                    if scope_row is None:
                        db.execute(
                            "INSERT INTO ledger_meta (key, value) VALUES "
                            "('scope_fingerprint', ?)",
                            (self.scope_fingerprint,),
                        )
                    elif str(scope_row["value"]) != self.scope_fingerprint:
                        raise RuntimeError(
                            "ledger scope does not match the configured Hindsight "
                            "bank/user/project; choose a new state directory"
                        )
                db.execute(
                    "UPDATE runs SET status = 'failed', "
                    "error = 'legacy pending run requires retry', completed_at = ? "
                    "WHERE status = 'pending'",
                    (utc_now(),),
                )
                db.execute(
                    "UPDATE runs SET status = 'failed', "
                    "error = 'legacy processing run requires retry', completed_at = ? "
                    "WHERE status = 'processing' AND (claim_id IS NULL OR claim_id = '')",
                    (utc_now(),),
                )
                db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
                self._secure_files()

    @staticmethod
    def _prune_seen_evidence(db: sqlite3.Connection) -> int:
        """Expire dedupe tombstones only after the maximum capture lookback.

        The adapter allows at most a 30-day backfill.  Five extra days prevent
        a reviewed row pruned from the active ledger from reappearing during a
        forced scan at the boundary.
        """
        cutoff = (
            datetime.now(timezone.utc)
            - timedelta(days=SEEN_EVIDENCE_RETENTION_DAYS)
        ).isoformat()
        return db.execute(
            "DELETE FROM seen_evidence WHERE seen_at < ?",
            (cutoff,),
        ).rowcount

    @staticmethod
    def _insert_exchange(db: sqlite3.Connection, exchange: Exchange) -> bool:
        if db.execute(
            "SELECT 1 FROM seen_evidence WHERE evidence_id = ?",
            (exchange.evidence_id,),
        ).fetchone():
            return False
        now = utc_now()
        cursor = db.execute(
            """
            INSERT OR IGNORE INTO exchanges (
                evidence_id, session_key, observed_at, user_text, assistant_final,
                tool_events_json, source, coverage, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                exchange.evidence_id,
                exchange.session_key,
                exchange.observed_at,
                exchange.user_text,
                exchange.assistant_final,
                canonical_json([asdict(event) for event in exchange.tool_events]),
                exchange.source,
                exchange.coverage,
                now,
            ),
        )
        # Preserve a dedupe record even if a legacy exchange row existed
        # without one.  Deleting an exchange during pruning never deletes this
        # tombstone, so forced session backfill cannot churn reviewed evidence.
        db.execute(
            "INSERT OR IGNORE INTO seen_evidence "
            "(evidence_id, observed_at, seen_at) VALUES (?, ?, ?)",
            (exchange.evidence_id, exchange.observed_at, now),
        )
        return cursor.rowcount == 1

    def add_exchange(self, exchange: Exchange) -> bool:
        with self._lock, self._database() as db:
            return self._insert_exchange(db, exchange)

    @staticmethod
    def _delete_exchange_ids(
        db: sqlite3.Connection,
        evidence_ids: Sequence[str],
    ) -> tuple[int, int]:
        candidates_deleted = 0
        exchanges_deleted = 0
        for start in range(0, len(evidence_ids), 400):
            batch = list(evidence_ids[start : start + 400])
            placeholders = ",".join("?" for _ in batch)
            candidates_deleted += db.execute(
                f"DELETE FROM candidates WHERE evidence_id IN ({placeholders})",
                batch,
            ).rowcount
            exchanges_deleted += db.execute(
                f"DELETE FROM exchanges WHERE evidence_id IN ({placeholders})",
                batch,
            ).rowcount
        return candidates_deleted, exchanges_deleted

    @classmethod
    def _prune_reviewed_to_limit(
        cls,
        db: sqlite3.Connection,
        max_exchanges: int,
    ) -> tuple[int, int, int, int]:
        before = int(db.execute("SELECT COUNT(*) FROM exchanges").fetchone()[0])
        excess = max(0, before - max_exchanges)
        if not excess:
            return before, before, 0, 0
        rows = db.execute(
            """
            SELECT e.evidence_id
            FROM exchanges AS e
            WHERE e.reviewed_run IS NOT NULL
              AND e.status NOT IN ('pending', 'processing', 'retry')
              AND NOT EXISTS (
                  SELECT 1 FROM candidates AS c
                  WHERE c.evidence_id = e.evidence_id
                    AND c.status NOT IN ('retained', 'rejected', 'proposed')
              )
            ORDER BY e.observed_at, e.evidence_id
            LIMIT ?
            """,
            (excess,),
        ).fetchall()
        evidence_ids = [str(row["evidence_id"]) for row in rows]
        candidates_deleted, exchanges_deleted = cls._delete_exchange_ids(
            db, evidence_ids
        )
        after = before - exchanges_deleted
        return before, after, candidates_deleted, exchanges_deleted

    def add_exchange_bounded(
        self,
        exchange: Exchange,
        max_exchanges: int,
    ) -> str:
        """Insert within a hard cap, or defer when only active evidence remains.

        Returns ``inserted``, ``duplicate``, or ``deferred``.  Reviewed evidence
        is pruned transactionally to make room; unreviewed, retrying, and
        processing evidence is never evicted for a new session snapshot.
        """
        max_exchanges = max(1, min(int(max_exchanges), 100_000))
        with self._lock:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                self._prune_seen_evidence(db)
                duplicate = db.execute(
                    "SELECT 1 FROM seen_evidence WHERE evidence_id = ? "
                    "UNION SELECT 1 FROM exchanges WHERE evidence_id = ?",
                    (exchange.evidence_id, exchange.evidence_id),
                ).fetchone()
                if duplicate:
                    db.rollback()
                    return "duplicate"
                self._prune_reviewed_to_limit(db, max_exchanges - 1)
                count = int(db.execute("SELECT COUNT(*) FROM exchanges").fetchone()[0])
                if count >= max_exchanges:
                    db.commit()
                    return "deferred"
                inserted = self._insert_exchange(db, exchange)
                db.commit()
                return "inserted" if inserted else "duplicate"
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
                self._secure_files()

    def prune_exchanges(self, max_exchanges: int) -> dict[str, int]:
        """Prune oldest safely reviewed evidence while preserving active work."""
        max_exchanges = max(1, min(int(max_exchanges), 100_000))
        with self._lock:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                before, after, candidates_deleted, exchanges_deleted = (
                    self._prune_reviewed_to_limit(db, max_exchanges)
                )
                seen_expired = self._prune_seen_evidence(db)
                active_preserved = int(
                    db.execute(
                        "SELECT COUNT(*) FROM exchanges WHERE reviewed_run IS NULL "
                        "OR status IN ('pending', 'processing', 'retry')"
                    ).fetchone()[0]
                )
                db.commit()
                return {
                    "exchanges_before": before,
                    "exchanges_after": after,
                    "exchanges_deleted": exchanges_deleted,
                    "candidates_deleted": candidates_deleted,
                    "active_preserved": active_preserved,
                    "at_or_below_limit": int(after <= max_exchanges),
                    "seen_expired": seen_expired,
                }
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
                self._secure_files()

    @staticmethod
    def _row_exchange(row: sqlite3.Row) -> Exchange:
        events = [ToolEvent(**item) for item in json.loads(row["tool_events_json"])]
        return Exchange(
            evidence_id=row["evidence_id"],
            session_key=row["session_key"],
            observed_at=row["observed_at"],
            user_text=row["user_text"],
            assistant_final=row["assistant_final"],
            tool_events=events,
            source=row["source"],
            coverage=row["coverage"],
        )

    def get_exchange(self, evidence_id: str) -> Exchange | None:
        with self._lock, self._database() as db:
            row = db.execute(
                "SELECT * FROM exchanges WHERE evidence_id = ?", (evidence_id,)
            ).fetchone()
            return self._row_exchange(row) if row else None

    def discard_exchange(self, evidence_id: str, observed_at: str = "unset") -> None:
        """Tombstone and remove evidence that must never enter automated review."""
        normalized_id = clean_text(evidence_id, 128)
        if not normalized_id:
            return
        now = utc_now()
        with self._lock:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "INSERT INTO seen_evidence (evidence_id, observed_at, seen_at) "
                    "VALUES (?, ?, ?) ON CONFLICT(evidence_id) DO UPDATE SET "
                    "seen_at = excluded.seen_at",
                    (normalized_id, clean_text(observed_at, 80) or "unset", now),
                )
                db.execute(
                    "DELETE FROM memory_keys WHERE candidate_id IN "
                    "(SELECT candidate_id FROM candidates WHERE evidence_id = ?)",
                    (normalized_id,),
                )
                db.execute("DELETE FROM candidates WHERE evidence_id = ?", (normalized_id,))
                db.execute("DELETE FROM exchanges WHERE evidence_id = ?", (normalized_id,))
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
                self._secure_files()

    def purge_opt_out_exchanges(self) -> int:
        """Remove legacy captures whose user explicitly opted out of automation."""
        with self._lock, self._database() as db:
            rows = db.execute(
                "SELECT evidence_id, observed_at, user_text FROM exchanges"
            ).fetchall()
        opted_out = [
            (str(row["evidence_id"]), str(row["observed_at"]))
            for row in rows
            if memory_opt_out(str(row["user_text"]))
        ]
        for evidence_id, observed_at in opted_out:
            self.discard_exchange(evidence_id, observed_at)
        return len(opted_out)

    def pending_exchanges(self, limit: int) -> list[Exchange]:
        """Read available work without claiming it; prefer :meth:`claim_exchanges`."""
        with self._lock, self._database() as db:
            rows = db.execute(
                "SELECT * FROM exchanges WHERE status IN ('pending', 'retry') "
                "AND reviewed_run IS NULL "
                "AND (next_attempt_at IS NULL OR next_attempt_at <= ?) "
                "ORDER BY observed_at LIMIT ?",
                (utc_now(), limit),
            ).fetchall()
            return [self._row_exchange(row) for row in rows]

    def claim_exchanges(
        self,
        limit: int,
        owner: str,
        lease_seconds: int = 120,
    ) -> list[Exchange]:
        """Atomically lease available exchanges to one worker.

        Expired leases are recovered in the same write transaction.  Claiming
        increments ``attempts``; retry delay is calculated when a worker marks
        its claim as ``retry``.
        """
        normalized_owner = clean_text(owner, 128)
        if not normalized_owner:
            raise ValueError("claim owner must not be empty")
        limit = max(1, min(int(limit), 1_000))
        lease_seconds = max(5, min(int(lease_seconds), 3_600))
        now_value = datetime.now(timezone.utc)
        now = now_value.isoformat()
        lease_until = (now_value + timedelta(seconds=lease_seconds)).isoformat()
        with self._lock:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    """
                    UPDATE exchanges
                    SET status = 'retry', lease_owner = NULL, lease_until = NULL,
                        next_attempt_at = NULL,
                        error = CASE WHEN error = '' THEN 'processing lease expired' ELSE error END
                    WHERE status = 'processing' AND lease_until IS NOT NULL AND lease_until <= ?
                    """,
                    (now,),
                )
                rows = db.execute(
                    """
                    SELECT * FROM exchanges
                    WHERE status IN ('pending', 'retry')
                      AND reviewed_run IS NULL
                      AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
                    ORDER BY observed_at, evidence_id
                    LIMIT ?
                    """,
                    (now, limit),
                ).fetchall()
                evidence_ids = [str(row["evidence_id"]) for row in rows]
                if evidence_ids:
                    placeholders = ",".join("?" for _ in evidence_ids)
                    db.execute(
                        f"""
                        UPDATE exchanges
                        SET status = 'processing', lease_owner = ?, lease_until = ?,
                            attempts = attempts + 1, next_attempt_at = NULL
                        WHERE evidence_id IN ({placeholders})
                          AND status IN ('pending', 'retry')
                        """,
                        (normalized_owner, lease_until, *evidence_ids),
                    )
                db.commit()
                return [self._row_exchange(row) for row in rows]
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
                self._secure_files()

    def mark_exchange(
        self,
        evidence_id: str,
        status: str,
        error: str = "",
        owner: str | None = None,
    ) -> bool:
        """Finish or retry an exchange claim.

        Supplying ``owner`` prevents a stale worker from updating a claim that
        has already expired and been leased elsewhere.  Retry delays begin at
        30 seconds and cap at one hour.
        """
        if status not in {"pending", "processed", "retry", "failed", "blocked"}:
            raise ValueError(f"unsupported exchange status: {status}")
        with self._lock:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT lease_owner, attempts FROM exchanges WHERE evidence_id = ?",
                    (evidence_id,),
                ).fetchone()
                if row is None or (owner is not None and row["lease_owner"] != owner):
                    db.rollback()
                    return False
                next_attempt_at: str | None = None
                if status == "retry":
                    attempts = max(1, int(row["attempts"] or 0))
                    delay = min(3_600, 30 * (2 ** min(attempts - 1, 7)))
                    next_attempt_at = (
                        datetime.now(timezone.utc) + timedelta(seconds=delay)
                    ).isoformat()
                cursor = db.execute(
                    """
                    UPDATE exchanges
                    SET status = ?, error = ?, lease_owner = NULL, lease_until = NULL,
                        next_attempt_at = ?
                    WHERE evidence_id = ?
                    """,
                    (
                        status,
                        clean_text(error, 1_000),
                        next_attempt_at,
                        evidence_id,
                    ),
                )
                db.commit()
                return cursor.rowcount == 1
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
                self._secure_files()

    def save_candidate(self, candidate: Candidate) -> None:
        with self._lock, self._database() as db:
            db.execute(
                """
                INSERT INTO candidates (
                    candidate_id, evidence_id, category, content, memory_key,
                    confidence, verified, sensitivity, status, reason, operation_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(candidate_id) DO UPDATE SET
                    status = CASE
                        WHEN candidates.status = 'retained'
                         AND excluded.status != 'retained' THEN candidates.status
                        ELSE excluded.status
                    END,
                    reason = CASE
                        WHEN candidates.status = 'retained'
                         AND excluded.status != 'retained' THEN candidates.reason
                        ELSE excluded.reason
                    END,
                    operation_id = CASE
                        WHEN candidates.status = 'retained'
                         AND excluded.status != 'retained' THEN candidates.operation_id
                        ELSE COALESCE(excluded.operation_id, candidates.operation_id)
                    END
                """,
                (
                    candidate.candidate_id,
                    candidate.evidence_id,
                    candidate.category,
                    candidate.content,
                    candidate.memory_key,
                    candidate.confidence,
                    int(candidate.verified),
                    candidate.sensitivity,
                    candidate.status,
                    candidate.reason,
                    candidate.operation_id,
                    utc_now(),
                ),
            )
            if candidate.memory_key and candidate.status in {
                "proposed",
                "retain_error",
                "retained",
            }:
                db.execute(
                    """
                    UPDATE candidates
                    SET status = 'rejected',
                        reason = 'superseded by a canonical nightly memory candidate'
                    WHERE evidence_id = ? AND category = ?
                      AND status = 'needs_key_review' AND candidate_id != ?
                    """,
                    (
                        candidate.evidence_id,
                        candidate.category,
                        candidate.candidate_id,
                    ),
                )

    def reserve_memory_key(self, candidate: Candidate) -> tuple[bool, str | None]:
        """Reserve a mutable memory identity without value-derived fuzzy matching."""
        if candidate.category not in MUTABLE_CATEGORIES:
            return False, "immutable memories must not reserve a memory_key"
        memory_key = candidate.memory_key or ""
        key_error = _memory_key_error(candidate.category, memory_key)
        if key_error:
            return False, key_error
        expected_key = canonical_memory_key(candidate.category, candidate.content)
        if expected_key is None or memory_key != expected_key:
            return False, (
                "memory_key is unrelated to the locally derived canonical identity "
                "for this topic"
            )
        if not _memory_key_matches_content(memory_key, candidate.content):
            return False, (
                "memory_key topic is not supported by candidate content; "
                "it may refer to an unrelated topic"
            )
        document_id = candidate.document_id
        now = utc_now()
        with self._lock:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT * FROM memory_keys WHERE memory_key = ?",
                    (memory_key,),
                ).fetchone()
                if row is None:
                    document_owner = db.execute(
                        "SELECT memory_key FROM memory_keys WHERE document_id = ?",
                        (document_id,),
                    ).fetchone()
                    if document_owner:
                        db.rollback()
                        return False, "document identity is owned by a different memory_key"
                    db.execute(
                        """
                        INSERT INTO memory_keys (
                            memory_key, document_id, category, anchor_text, candidate_id,
                            created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            memory_key,
                            document_id,
                            candidate.category,
                            "",
                            candidate.candidate_id,
                            now,
                            now,
                        ),
                    )
                    db.commit()
                    return True, None
                if str(row["category"]) != candidate.category:
                    db.rollback()
                    return False, "memory_key is owned by a different category"
                if str(row["document_id"]) != document_id:
                    db.rollback()
                    return False, "memory_key document identity does not match its owner"
                db.execute(
                    "UPDATE memory_keys SET candidate_id = ?, updated_at = ? "
                    "WHERE memory_key = ?",
                    (candidate.candidate_id, now, memory_key),
                )
                db.commit()
                return True, None
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
                self._secure_files()

    def claim_memory_write(
        self,
        memory_key: str,
        candidate_id: str,
        observed_at: str,
        owner: str,
        lease_seconds: int = 180,
    ) -> tuple[bool, str | None]:
        """Fence a mutable remote upsert across plugin instances and processes."""
        normalized_owner = clean_text(owner, 160)
        if not normalized_owner:
            return False, "memory write owner is empty"
        incoming_order = observation_order(observed_at, candidate_id)
        now_value = datetime.now(timezone.utc)
        now = now_value.isoformat()
        lease_until = (
            now_value
            + timedelta(seconds=max(30, min(int(lease_seconds), 3_600)))
        ).isoformat()
        with self._lock:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT * FROM memory_keys WHERE memory_key = ?",
                    (memory_key,),
                ).fetchone()
                if row is None:
                    db.rollback()
                    return False, "memory key has not been reserved"
                active_owner = str(row["write_owner"] or "")
                active_until = str(row["write_lease_until"] or "")
                if active_owner and active_until > now:
                    db.rollback()
                    return False, "another memory write is still in progress"
                latest_at = str(row["latest_observed_at"] or "")
                latest_candidate = str(row["latest_candidate_id"] or "")
                if latest_at and incoming_order < observation_order(
                    latest_at, latest_candidate
                ):
                    db.rollback()
                    return False, "candidate is older than the latest committed memory value"
                local_rows = db.execute(
                    "SELECT e.observed_at, c.candidate_id FROM candidates AS c "
                    "JOIN exchanges AS e ON e.evidence_id = c.evidence_id "
                    "WHERE c.memory_key = ? AND c.status IN "
                    "('proposed', 'needs_key_review', 'retain_error', 'retained')",
                    (memory_key,),
                ).fetchall()
                newest_local = (
                    max(
                        local_rows,
                        key=lambda item: observation_order(
                            str(item["observed_at"]),
                            str(item["candidate_id"]),
                        ),
                    )
                    if local_rows
                    else None
                )
                if newest_local and incoming_order < observation_order(
                    str(newest_local["observed_at"]),
                    str(newest_local["candidate_id"]),
                ):
                    db.rollback()
                    return False, "candidate is older than a newer locally accepted value"
                db.execute(
                    "UPDATE memory_keys SET write_owner = ?, write_lease_until = ?, "
                    "write_observed_at = ?, write_candidate_id = ? WHERE memory_key = ?",
                    (
                        normalized_owner,
                        lease_until,
                        incoming_order[0],
                        incoming_order[1],
                        memory_key,
                    ),
                )
                db.commit()
                return True, None
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
                self._secure_files()

    def complete_memory_write(self, memory_key: str, owner: str) -> bool:
        """Commit chronology only if this caller still owns the write lease."""
        normalized_owner = clean_text(owner, 160)
        with self._lock:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT * FROM memory_keys WHERE memory_key = ?",
                    (memory_key,),
                ).fetchone()
                if row is None or str(row["write_owner"] or "") != normalized_owner:
                    db.rollback()
                    return False
                write_at = str(row["write_observed_at"] or "")
                write_candidate = str(row["write_candidate_id"] or "")
                latest_at = str(row["latest_observed_at"] or "")
                latest_candidate = str(row["latest_candidate_id"] or "")
                if not latest_at or observation_order(
                    write_at, write_candidate
                ) >= observation_order(latest_at, latest_candidate):
                    latest_at = write_at
                    latest_candidate = write_candidate
                db.execute(
                    "UPDATE memory_keys SET latest_observed_at = ?, "
                    "latest_candidate_id = ?, write_owner = NULL, "
                    "write_lease_until = NULL, write_observed_at = NULL, "
                    "write_candidate_id = NULL, updated_at = ? WHERE memory_key = ?",
                    (latest_at, latest_candidate, utc_now(), memory_key),
                )
                db.commit()
                return True
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
                self._secure_files()

    def release_memory_write(self, memory_key: str, owner: str) -> bool:
        """Release a lease only after the remote request has definitively ended."""
        with self._lock, self._database() as db:
            cursor = db.execute(
                "UPDATE memory_keys SET write_owner = NULL, write_lease_until = NULL, "
                "write_observed_at = NULL, write_candidate_id = NULL "
                "WHERE memory_key = ? AND write_owner = ?",
                (memory_key, clean_text(owner, 160)),
            )
            return cursor.rowcount == 1

    def queued_candidates(self, limit: int = 100) -> list[Candidate]:
        with self._lock, self._database() as db:
            rows = db.execute(
                "SELECT * FROM candidates WHERE status = 'queued' AND operation_id IS NOT NULL "
                "ORDER BY created_at LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._row_candidate(row) for row in rows]

    @staticmethod
    def _row_candidate(row: sqlite3.Row) -> Candidate:
        return Candidate(
            candidate_id=row["candidate_id"],
            evidence_id=row["evidence_id"],
            category=row["category"],
            content=row["content"],
            memory_key=row["memory_key"],
            confidence=float(row["confidence"]),
            verified=bool(row["verified"]),
            sensitivity=row["sensitivity"],
            status=row["status"],
            reason=row["reason"],
            operation_id=row["operation_id"],
        )

    def candidates_for(self, evidence_ids: Sequence[str]) -> list[Candidate]:
        if not evidence_ids:
            return []
        placeholders = ",".join("?" for _ in evidence_ids)
        with self._lock, self._database() as db:
            rows = db.execute(
                f"SELECT * FROM candidates WHERE evidence_id IN ({placeholders}) ORDER BY created_at",
                tuple(evidence_ids),
            ).fetchall()
            return [self._row_candidate(row) for row in rows]

    def recent_calibration_candidates(
        self,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Return a private, sanitized newest-first memory-calibration view."""
        if limit <= 0:
            return []
        limit = min(int(limit), 20)
        with self._lock, self._database() as db:
            rows = db.execute(
                """
                SELECT c.*, e.observed_at
                FROM candidates AS c
                JOIN exchanges AS e ON e.evidence_id = c.evidence_id
                WHERE c.sensitivity IN ('normal', 'sensitive')
                  AND c.status IN (
                      'proposed', 'needs_key_review', 'retain_error', 'retained'
                  )
                ORDER BY c.created_at DESC, c.candidate_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            result: list[dict[str, Any]] = []
            for row in rows:
                content = redact_secrets(str(row["content"]), 280)
                if str(row["sensitivity"]) == "sensitive" and not contains_health_data(
                    content
                ):
                    continue
                result.append({
                    "candidate_id": str(row["candidate_id"]),
                    "evidence_id": str(row["evidence_id"]),
                    "observed_at": str(row["observed_at"]),
                    "category": str(row["category"]),
                    "memory_key": row["memory_key"],
                    "status": str(row["status"]),
                    "content": content,
                })
            return result[:limit]

    def save_private_findings(
        self, run_id: str, findings: Sequence[dict[str, Any]]
    ) -> None:
        """Persist validated full findings only in the private SQLite state."""
        now = utc_now()
        with self._lock, self._database() as db:
            for finding in findings[:30]:
                finding_id = clean_text(finding.get("finding_id"), 128)
                if not finding_id:
                    continue
                payload = canonical_json(finding)
                if len(payload) > 16_000:
                    continue
                db.execute(
                    "INSERT INTO private_findings "
                    "(finding_id, run_id, payload_json, created_at) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(finding_id) DO UPDATE SET run_id = excluded.run_id, "
                    "payload_json = excluded.payload_json, created_at = excluded.created_at",
                    (finding_id, clean_text(run_id, 160), payload, now),
                )
            db.execute(
                "DELETE FROM private_findings WHERE finding_id NOT IN "
                "(SELECT finding_id FROM private_findings "
                "ORDER BY created_at DESC, finding_id DESC LIMIT 100)"
            )

    def recent_private_findings(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return validated findings for an explicitly authorized private view."""
        limit = max(0, min(int(limit), 20))
        if not limit:
            return []
        with self._lock, self._database() as db:
            rows = db.execute(
                "SELECT payload_json FROM private_findings "
                "ORDER BY created_at DESC, finding_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        def current_redaction(value: Any, depth: int = 0) -> Any:
            if depth > 12:
                return "[REDACTED_DEPTH]"
            if isinstance(value, str):
                return redact_secrets(clean_text(value, 2_000), 2_000)
            if isinstance(value, list):
                return [current_redaction(item, depth + 1) for item in value[:50]]
            if isinstance(value, dict):
                return {
                    clean_text(key, 120): current_redaction(item, depth + 1)
                    for key, item in list(value.items())[:50]
                }
            if isinstance(value, (bool, int, float)) or value is None:
                return value
            return clean_text(value, 500)

        findings: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(str(row["payload_json"]))
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                findings.append(current_redaction(payload))
        return findings

    def unreviewed_exchanges(self, limit: int) -> list[Exchange]:
        with self._lock, self._database() as db:
            rows = db.execute(
                "SELECT * FROM exchanges WHERE reviewed_run IS NULL "
                "ORDER BY observed_at, evidence_id LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._row_exchange(row) for row in rows]

    def recent_reviewed_exchanges(
        self,
        limit: int,
        exclude_evidence_ids: Sequence[str] = (),
    ) -> list[Exchange]:
        """Select the newest reviewed baseline and return it chronologically."""
        if limit <= 0:
            return []
        limit = min(int(limit), 500)
        excluded = list(dict.fromkeys(str(item) for item in exclude_evidence_ids))[:500]
        where = "reviewed_run IS NOT NULL"
        parameters: list[Any] = []
        if excluded:
            placeholders = ",".join("?" for _ in excluded)
            where += f" AND evidence_id NOT IN ({placeholders})"
            parameters.extend(excluded)
        parameters.append(limit)
        with self._lock, self._database() as db:
            rows = db.execute(
                f"SELECT * FROM exchanges WHERE {where} "
                "ORDER BY observed_at DESC, evidence_id DESC LIMIT ?",
                parameters,
            ).fetchall()
            rows.reverse()
            return [self._row_exchange(row) for row in rows]

    def create_run(
        self,
        run_id: str,
        evidence_ids: Sequence[str],
        bundle_path: Path | None = None,
        report_path: Path | None = None,
        stale_after_seconds: int = 3_600,
    ) -> str | None:
        """Create and claim a nightly run exactly once.

        ``bundle_path`` is retained only for migration compatibility.  New runs
        should leave it unset because raw evidence is not written to Git.  A
        crashed processing claim can be reclaimed after the bounded stale
        interval; completed runs can never be reclaimed.  The returned claim
        token must be supplied to ``complete_run`` or ``fail_run``.
        """
        with self._lock, self._database() as db:
            evidence_json = canonical_json(list(dict.fromkeys(evidence_ids)))
            bundle_value = str(bundle_path) if bundle_path else ""
            report_value = str(report_path) if report_path else None
            now_value = datetime.now(timezone.utc)
            created_at = now_value.isoformat()
            stale_after_seconds = max(300, min(int(stale_after_seconds), 86_400))
            stale_before = (
                now_value - timedelta(seconds=stale_after_seconds)
            ).isoformat()
            claim_id = str(uuid.uuid4())
            cursor = db.execute(
                "INSERT OR IGNORE INTO runs "
                "(run_id, evidence_ids_json, bundle_path, report_path, status, claim_id, created_at) "
                "VALUES (?, ?, ?, ?, 'processing', ?, ?)",
                (
                    run_id,
                    evidence_json,
                    bundle_value,
                    report_value,
                    claim_id,
                    created_at,
                ),
            )
            if cursor.rowcount == 1:
                return claim_id
            retry = db.execute(
                """
                UPDATE runs
                SET evidence_ids_json = ?, bundle_path = ?, report_path = ?,
                    status = 'processing', claim_id = ?, error = '', created_at = ?,
                    completed_at = NULL
                WHERE run_id = ? AND (
                    status = 'failed'
                    OR (status = 'processing' AND created_at <= ?)
                )
                """,
                (
                    evidence_json,
                    bundle_value,
                    report_value,
                    claim_id,
                    created_at,
                    run_id,
                    stale_before,
                ),
            )
            return claim_id if retry.rowcount == 1 else None

    def run_status(self, run_id: str) -> dict[str, Any] | None:
        with self._lock, self._database() as db:
            row = db.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if not row:
                return None
            bundle_path = str(row["bundle_path"] or "")
            return {
                "run_id": str(row["run_id"]),
                "evidence_ids": list(json.loads(row["evidence_ids_json"])),
                "bundle_path": bundle_path or None,
                "report_path": row["report_path"],
                "status": str(row["status"]),
                "claim_id": row["claim_id"],
                "error": str(row["error"] or ""),
                "created_at": str(row["created_at"]),
                "completed_at": row["completed_at"],
            }

    def run_evidence_ids(self, run_id: str) -> list[str]:
        with self._lock, self._database() as db:
            row = db.execute(
                "SELECT evidence_ids_json FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            return list(json.loads(row[0])) if row else []

    def run_exists(self, run_id: str) -> bool:
        return self.run_status(run_id) is not None

    def complete_run(self, run_id: str, report_path: Path, claim_id: str) -> bool:
        with self._lock:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT evidence_ids_json, status FROM runs "
                    "WHERE run_id = ? AND claim_id = ?",
                    (run_id, claim_id),
                ).fetchone()
                if not row or row["status"] != "processing":
                    db.rollback()
                    return False
                evidence_ids = list(json.loads(row["evidence_ids_json"]))
                db.execute(
                    "UPDATE runs SET status = 'complete', report_path = ?, "
                    "completed_at = ?, error = '' WHERE run_id = ? "
                    "AND status = 'processing' AND claim_id = ?",
                    (str(report_path), utc_now(), run_id, claim_id),
                )
                if evidence_ids:
                    placeholders = ",".join("?" for _ in evidence_ids)
                    db.execute(
                        f"UPDATE exchanges SET reviewed_run = ?, status = 'processed', "
                        f"lease_owner = NULL, lease_until = NULL, "
                        f"next_attempt_at = NULL, error = '' "
                        f"WHERE evidence_id IN ({placeholders})",
                        (run_id, *evidence_ids),
                    )
                db.commit()
                return True
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
                self._secure_files()

    def fail_run(self, run_id: str, error: str, claim_id: str) -> bool:
        with self._lock, self._database() as db:
            cursor = db.execute(
                "UPDATE runs SET status = 'failed', error = ?, completed_at = ? "
                "WHERE run_id = ? AND status = 'processing' AND claim_id = ?",
                (clean_text(error, 1_000), utc_now(), run_id, claim_id),
            )
            return cursor.rowcount == 1

    def counts(self) -> dict[str, int]:
        with self._lock, self._database() as db:
            exchange_count = db.execute("SELECT COUNT(*) FROM exchanges").fetchone()[0]
            pending = db.execute(
                "SELECT COUNT(*) FROM exchanges WHERE status IN ('pending', 'retry')"
            ).fetchone()[0]
            proposed = db.execute(
                "SELECT COUNT(*) FROM candidates WHERE status = 'proposed'"
            ).fetchone()[0]
            queued = db.execute(
                "SELECT COUNT(*) FROM candidates WHERE status = 'queued'"
            ).fetchone()[0]
            return {
                "exchanges": int(exchange_count),
                "pending_exchanges": int(pending),
                "proposed_candidates": int(proposed),
                "queued_operations": int(queued),
            }


def safe_write_markdown(workspace: Path, path: Path, content: str) -> Path:
    """Atomically write one Markdown file below ``workspace``.

    Resolution is repeated after creating the parent directory so a symlinked
    parent cannot redirect the write outside the workspace.  ``os.replace``
    makes readers see either the old complete report or the new complete one.
    """
    root = workspace.resolve()
    target = path if path.is_absolute() else root / path
    if target.suffix.lower() != ".md":
        raise ValueError("report path must end in .md")
    try:
        existing_ancestor = target.parent
        while not existing_ancestor.exists() and existing_ancestor != existing_ancestor.parent:
            existing_ancestor = existing_ancestor.parent
        existing_ancestor.resolve(strict=True).relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        resolved_parent = target.parent.resolve(strict=True)
        resolved_parent.relative_to(root)
    except (OSError, ValueError) as exc:
        raise ValueError("report path must stay inside the workspace") from exc
    resolved_target = resolved_parent / target.name
    if resolved_target.exists() and resolved_target.is_dir():
        raise ValueError("report path points to a directory")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.stem}.", suffix=".tmp", dir=resolved_parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            if content and not content.endswith("\n"):
                stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, resolved_target)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    return resolved_target


def inventory_skills(workspace: Path, roots: Sequence[Path]) -> list[dict[str, str]]:
    inventory: list[dict[str, str]] = []
    workspace_resolved = workspace.resolve()
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("SKILL.md")):
            try:
                resolved = path.resolve()
                resolved.relative_to(workspace_resolved)
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError, ValueError):
                continue
            name_match = re.search(r"(?im)^name:\s*[\"']?([^\n\"']+)", content[:2_000])
            description_match = re.search(
                r"(?im)^description:\s*[\"']?([^\n\"']+)", content[:3_000]
            )
            heading_match = re.search(r"(?m)^#\s+(.+)$", content[:3_000])
            relative = resolved.relative_to(workspace_resolved).as_posix()
            inventory.append(
                {
                    "name": redact_secrets(
                        clean_text(
                            (name_match or heading_match).group(1)
                            if (name_match or heading_match)
                            else path.parent.name,
                            120,
                        ),
                        120,
                    ),
                    "description": redact_secrets(
                        clean_text(
                            description_match.group(1) if description_match else "", 300
                        ),
                        300,
                    ),
                    "path": relative,
                    "sha256": stable_hash(content),
                }
            )
    return inventory


def validate_relative_paths(paths: Iterable[Any], workspace: Path) -> tuple[list[str], list[str]]:
    valid: list[str] = []
    rejected: list[str] = []
    root = workspace.resolve()
    for raw in paths:
        value = str(raw)
        candidate = Path(value)
        try:
            if candidate.is_absolute():
                raise ValueError
            (root / candidate).resolve().relative_to(root)
        except ValueError:
            rejected.append(value)
        else:
            valid.append(candidate.as_posix())
    return valid, rejected


_REVIEW_STOP_WORDS = frozenset(
    {
        "about", "again", "assistant", "could", "create", "does", "doing",
        "help", "make", "need", "please", "should", "task", "that", "this",
        "using", "want", "with", "would", "your",
    }
)


def _review_tokens(text: str) -> set[str]:
    normalized: set[str] = set()
    for token in _word_set(re.sub(r"[-_]+", " ", text)):
        if token.endswith("ies") and len(token) > 4:
            token = f"{token[:-3]}y"
        elif token.endswith("s") and not token.endswith("ss") and len(token) > 4:
            token = token[:-1]
        if token not in _REVIEW_STOP_WORDS and not token.isdigit():
            normalized.add(token)
    return normalized


def _matching_installed_skill(
    task_pattern: str,
    skill_id: str,
    skills: Sequence[dict[str, str]],
) -> str | None:
    proposal_tokens = _review_tokens(f"{task_pattern} {skill_id}")
    for skill in skills:
        name = clean_text(skill.get("name"), 120)
        skill_tokens = _review_tokens(
            f"{name} {clean_text(skill.get('description'), 300)}"
        )
        name_tokens = _review_tokens(name)
        overlap = proposal_tokens.intersection(skill_tokens)
        if name_tokens and name_tokens.issubset(proposal_tokens):
            return str(skill.get("path") or name)
        if len(overlap) >= 2 and len(overlap) / max(
            1, min(len(proposal_tokens), len(skill_tokens))
        ) >= 0.5:
            return str(skill.get("path") or name)
    return None


def _skill_refs_match(skill_id: str, refs: Iterable[str]) -> bool:
    normalized_skill = slug(skill_id).replace(".", "-")
    for ref in refs:
        normalized_ref = ref.lower().replace("_", "-")
        if normalized_skill == Path(ref).parent.name.lower().replace("_", "-"):
            return True
        if normalized_skill in normalized_ref:
            return True
    return False


def _has_attributed_skill_outcome(
    exchange: Exchange,
    skill_id: str,
    status: str,
) -> bool:
    """Require outcome instrumentation on the same event as the skill reference.

    Merely reading ``SKILL.md`` and later seeing an unrelated tool result is not
    attribution.  OpenSpace or another observer can qualify by emitting one
    non-file-read tool event that names the skill and carries the outcome.
    """
    generic_load_tools = {
        "read",
        "read_file",
        "readfile",
        "view_file",
        "open_file",
    }
    return any(
        event.status == status
        and event.tool_name.strip().lower() not in generic_load_tools
        and _skill_refs_match(skill_id, event.skill_refs)
        for event in exchange.tool_events
    )


def validate_findings(
    findings: Sequence[Any],
    exchanges: dict[str, Exchange],
    workspace: Path,
    skills: Sequence[dict[str, str]] = (),
) -> tuple[list[dict[str, Any]], list[str]]:
    accepted: list[dict[str, Any]] = []
    rejected: list[str] = []
    for index, raw in enumerate(findings[:50]):
        if not isinstance(raw, dict):
            rejected.append(f"finding {index}: must be an object")
            continue
        kind = str(raw.get("kind") or "")
        evidence_ids = [str(item) for item in raw.get("evidence_ids") or []]
        if kind not in ALLOWED_FINDING_KINDS:
            rejected.append(f"finding {index}: unsupported kind")
            continue
        if not evidence_ids or any(item not in exchanges for item in evidence_ids):
            rejected.append(f"finding {index}: contains missing or unsupported evidence IDs")
            continue
        try:
            confidence = float(raw.get("confidence", 0))
        except (TypeError, ValueError):
            confidence = 0
        if not math.isfinite(confidence) or confidence < 0.65 or confidence > 1:
            rejected.append(f"finding {index}: confidence outside accepted range")
            continue
        skill_id = str(raw.get("skill_id") or "").strip()
        cited_exchanges = [exchanges[item] for item in dict.fromkeys(evidence_ids)]
        if kind == "existing_skill_failure" and (
            not skill_id
            or not any(
                _has_attributed_skill_outcome(exchange, skill_id, "error")
                for exchange in cited_exchanges
            )
        ):
            rejected.append(
                f"finding {index}: an existing-skill failure requires a directly "
                "instrumented skill outcome; use observation_gap for co-occurrence"
            )
            continue
        if kind == "missing_skill_opportunity" and len(set(evidence_ids)) < 2:
            rejected.append(
                f"finding {index}: missing-skill proposals require at least two observed exchanges"
            )
            continue
        if kind == "missing_skill_opportunity":
            task_pattern = clean_text(raw.get("task_pattern"), 400)
            pattern_tokens = _review_tokens(task_pattern)
            unique_evidence = list(dict.fromkeys(evidence_ids))
            required_overlap = (
                1 if len(pattern_tokens) == 1 else max(2, (len(pattern_tokens) + 1) // 2)
            )
            matching_requests = sum(
                len(
                    pattern_tokens.intersection(
                        _review_tokens(exchanges[evidence_id].user_text)
                    )
                )
                >= required_overlap
                for evidence_id in unique_evidence
            )
            if not pattern_tokens or matching_requests < 2:
                rejected.append(
                    f"finding {index}: task pattern does not recur across the cited user requests"
                )
                continue
            installed_match = _matching_installed_skill(
                task_pattern,
                skill_id,
                skills,
            )
            if installed_match:
                rejected.append(
                    f"finding {index}: proposed missing capability overlaps installed skill {installed_match}"
                )
                continue
        files, unsafe_files = validate_relative_paths(raw.get("files_to_consider") or [], workspace)
        if unsafe_files:
            rejected.append(f"finding {index}: contains unsafe file paths")
            continue
        proposed_action = str(raw.get("proposed_action") or "none")
        if proposed_action not in {
            "edit_existing",
            "create_new",
            "improve_routing",
            "observe_more",
            "none",
        }:
            rejected.append(f"finding {index}: unsupported proposed action")
            continue
        if kind == "skill_success" and (
            not skill_id
            or not any(
                _has_attributed_skill_outcome(exchange, skill_id, "success")
                for exchange in cited_exchanges
            )
        ):
            rejected.append(
                f"finding {index}: skill success requires a directly instrumented outcome"
            )
            continue
        finding = {
            "finding_id": stable_hash(
                {"kind": kind, "skill_id": skill_id, "evidence_ids": sorted(evidence_ids)}
            ),
            "kind": kind,
            "skill_id": skill_id or None,
            "task_pattern": redact_secrets(
                clean_text(raw.get("task_pattern"), 400), 400
            ),
            "evidence_ids": evidence_ids,
            "confidence": confidence,
            "severity": str(raw.get("severity") or "low")
            if str(raw.get("severity") or "low") in {"low", "medium", "high"}
            else "low",
            "evidence": redact_secrets(
                clean_text(raw.get("evidence"), 1_000), 1_000
            ),
            "inference": redact_secrets(
                clean_text(raw.get("inference"), 1_000), 1_000
            ),
            "proposed_action": proposed_action,
            "acceptance_test": redact_secrets(
                clean_text(raw.get("acceptance_test"), 700), 700
            ),
            "files_to_consider": files,
        }
        accepted.append(finding)
    return accepted, rejected


def render_final_report(
    run_id: str,
    summary: str,
    findings: Sequence[dict[str, Any]],
    rejected: Sequence[str],
    candidates: Sequence[Candidate],
) -> str:
    lines = [
        f"# Nightly Hindsight and skill review: {run_id}",
        "",
        "## Summary",
        "",
        redact_for_report(summary, 3_000)
        or "No changes are recommended from this evidence window.",
        "",
        "## Findings",
        "",
    ]
    if findings:
        for finding in findings:
            heading = redact_for_report(
                finding.get("task_pattern") or finding.get("skill_id") or "finding",
                240,
            )
            skill_id = redact_for_report(finding.get("skill_id"), 160)
            evidence = redact_for_report(finding.get("evidence"), 1_000)
            inference = redact_for_report(finding.get("inference"), 1_000)
            acceptance_test = redact_for_report(
                finding.get("acceptance_test"), 700
            )
            files = [
                redact_for_report(item, 300)
                for item in finding.get("files_to_consider") or []
            ]
            lines.extend(
                [
                    f"### {finding['kind']}: {heading}",
                    "",
                    f"- Severity: `{finding['severity']}`",
                    f"- Confidence: `{finding['confidence']:.2f}`",
                    f"- Evidence: {', '.join(f'`{item}`' for item in finding['evidence_ids'])}",
                    f"- Skill: `{skill_id}`" if skill_id else "- Skill: none observed",
                    f"- What happened: {evidence}",
                    f"- Inference: {inference}",
                    f"- Proposed action: `{finding['proposed_action']}`",
                    f"- Acceptance test: {acceptance_test}",
                    f"- Files to consider: {', '.join(f'`{item}`' for item in files) or 'none'}",
                    "",
                ]
            )
    else:
        lines.append("No evidence-backed skill change is recommended.")

    lines.extend(["", "## Memory gate", ""])
    if candidates:
        for candidate in candidates:
            lines.append(
                f"- `{candidate.status}` `{candidate.category}` from "
                f"`{candidate.evidence_id}`"
            )
    else:
        lines.append("No durable memory candidate passed the gate.")

    lines.extend(["", "## Rejected or uncertain proposals", ""])
    if rejected:
        lines.append(
            f"{len(rejected)} proposal(s) were rejected or deferred by local policy; "
            "details remain in private runtime state."
        )
    else:
        lines.append("None.")
    lines.extend(
        [
            "",
            "## Change policy",
            "",
            "The skill-review portion was report-only. It did not edit or create a skill, create a branch, commit, push, or merge. Durable-memory writes, if any, followed the configured Retain mode.",
            "",
        ]
    )
    return "\n".join(lines)
