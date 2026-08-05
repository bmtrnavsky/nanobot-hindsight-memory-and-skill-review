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
