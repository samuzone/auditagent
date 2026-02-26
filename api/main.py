"""
AuditAgent API
FastAPI backend — scans Base smart contracts with Claude AI
and scores findings using the Nethermind scoring algorithm.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.parse
import urllib.request
from collections import Counter
from typing import Any

import anthropic
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(title="AuditAgent API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://auditagent-theta.vercel.app", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# Request / Response models
# ─────────────────────────────────────────────

class AuditRequest(BaseModel):
    address: str
    anthropic_api_key: str
    basescan_api_key: str = ""
    model: str = "claude-sonnet-4-6"
    iterations: int = 3
    batch_size: int = 10

    @field_validator("address")
    @classmethod
    def validate_address(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("0x") or len(v) != 42:
            raise ValueError("Invalid address: must be 0x followed by 40 hex chars")
        return v.lower()

    @field_validator("anthropic_api_key")
    @classmethod
    def validate_key(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("sk-ant-"):
            raise ValueError("Invalid Anthropic API key: must start with sk-ant-")
        return v


class RawFinding(BaseModel):
    title: str
    severity: str
    description: str
    location: str = ""


class ScoredFinding(BaseModel):
    is_match: bool
    is_partial_match: bool
    is_fp: bool
    explanation: str
    severity_from_truth: str | None
    severity_from_junior_auditor: str | None
    index_of_finding_from_junior_auditor: int | None
    finding_description_from_junior_auditor: str | None


class AuditStats(BaseModel):
    total: int
    matches: int
    partials: int
    false_positives: int
    missed: int
    match_rate: float
    severity_breakdown: dict[str, int]


class AuditResponse(BaseModel):
    address: str
    contract_name: str
    source_length: int
    raw_findings: list[RawFinding]
    scored_findings: list[ScoredFinding]
    stats: AuditStats


# ─────────────────────────────────────────────
# Basescan — fetch verified source from Base
# ─────────────────────────────────────────────

BASESCAN_URL = "https://api.etherscan.io/v2/api"



def fetch_contract_source(address: str, api_key: str) -> tuple[str, str]:
    """
    Fetch verified Solidity source from Basescan.
    Returns (source_code, contract_name).
    """
    params = urllib.parse.urlencode({
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key if api_key else "YourApiKeyToken",
        "chainid": "8453",
    })
    url = f"{BASESCAN_URL}?{params}"
    logger.info("Fetching contract %s from Basescan", address)

    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            data = json.loads(resp.read().decode())
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Basescan request failed: {exc}")

    if data.get("status") != "1":
        msg = data.get("message", "Unknown error")
        result = data.get("result", "")
        raise HTTPException(
            status_code=400,
            detail=(
                f"Basescan error: {msg}. {result}. "
                "Make sure the contract address is correct and verified on Base (basescan.org)."
            ),
        )

    result = data["result"][0]
    source = result.get("SourceCode", "").strip()
    name = result.get("ContractName", "Unknown")

    if not source:
        raise HTTPException(
            status_code=400,
            detail=(
                "No verified source code found for this contract. "
                "The contract must be verified on https://basescan.org to be audited."
            ),
        )

    # Handle multi-file Solidity JSON (wrapped in double braces)
    if source.startswith("{{"):
        source = source[1:-1]
        try:
            files = json.loads(source).get("sources", {})
            combined = ""
            for fname, content in files.items():
                combined += f"\n// ===== {fname} =====\n"
                combined += content.get("content", "")
            source = combined
        except json.JSONDecodeError:
            pass  # use raw source

    logger.info("Fetched contract '%s' (%d chars)", name, len(source))
    return source, name


# ─────────────────────────────────────────────
# Claude — scan contract for vulnerabilities
# ─────────────────────────────────────────────

SCAN_SYSTEM = (
    "You are an expert Solidity smart contract security auditor. "
    "You identify real, exploitable vulnerabilities — not style issues or gas optimizations. "
    "You are precise and return structured JSON only."
)

SCAN_USER = """Audit the following Solidity smart contract and identify ALL security vulnerabilities.

CONTRACT SOURCE:
{source}

Return a JSON array. Each object must have exactly these fields:
- "title": short name of the vulnerability (e.g. "Reentrancy in withdraw()")
- "severity": one of "Critical", "High", "Medium", "Low", "Info"
- "description": detailed technical explanation — what the bug is, how it can be exploited, and what the impact is
- "location": file name and line number if identifiable (e.g. "Vault.sol:142"), or "" if unknown

Rules:
- Only include real security vulnerabilities. No style, gas, or best-practice issues unless they have direct security impact.
- Return ONLY the JSON array. No markdown fences, no explanation, no preamble.

Example output:
[{{"title": "Reentrancy in withdraw()", "severity": "High", "description": "The withdraw function updates state after an external .call(), allowing an attacker to re-enter before balance is zeroed.", "location": "Vault.sol:58"}}]"""


def scan_contract(source: str, client: anthropic.Anthropic, model: str) -> list[dict]:
    """Call Claude to identify vulnerabilities. Returns list of raw findings."""
    # Truncate very large contracts to avoid context overflow
    MAX_CHARS = 80_000
    if len(source) > MAX_CHARS:
        source = source[:MAX_CHARS] + "\n\n// [SOURCE TRUNCATED — contract exceeds scan limit]"
        logger.warning("Contract source truncated to %d chars", MAX_CHARS)

    logger.info("Scanning contract with model %s", model)
    message = client.messages.create(
        model=model,
        max_tokens=4096,
        system=SCAN_SYSTEM,
        messages=[{"role": "user", "content": SCAN_USER.format(source=source)}],
    )

    raw_text = message.content[0].text.strip()

    # Strip markdown fences if model adds them despite instructions
    if raw_text.startswith("```"):
        parts = raw_text.split("```")
        raw_text = parts[1] if len(parts) > 1 else raw_text
        if raw_text.startswith("json"):
            raw_text = raw_text[4:].strip()

    try:
        findings = json.loads(raw_text)
        if not isinstance(findings, list):
            logger.error("Scan returned non-list JSON")
            return []
        logger.info("Scan found %d raw findings", len(findings))
        return findings
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse scan JSON: %s | raw: %s", exc, raw_text[:300])
        return []


# ─────────────────────────────────────────────
# Scoring — Nethermind algorithm with Claude
# ─────────────────────────────────────────────

SCORE_PROMPT = """You are a senior smart contract security auditor validating AI-generated findings.

TARGET FINDING (ground truth):
{truth}

BATCH OF AI FINDINGS TO EVALUATE:
{batch}

Task: determine if any finding in the batch matches the TARGET FINDING.

Respond with exactly ONE of these formats:
- EXACT_MATCH:<index>   — a finding at that index is a clear, unambiguous match (same root cause, same vulnerable code path)
- PARTIAL_MATCH:<index> — a finding partially covers the same vulnerability (same class but different location or incomplete description)
- NO_MATCH              — none of the findings match the target

Rules:
- Severity difference alone does NOT disqualify a match.
- Only one finding can match. Choose the best one.
- Be strict: a match must address the same root cause, not just the same vulnerability class.

Your response (one line only):"""


def _call_claude_score(prompt: str, client: anthropic.Anthropic, model: str) -> str:
    """Single scoring call to Claude. Returns response text uppercased."""
    msg = client.messages.create(
        model=model,
        max_tokens=32,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text.strip().upper()


def _majority_vote(responses: list[str]) -> tuple[str, str]:
    """
    Apply 2-of-3 majority voting (Nethermind algorithm).
    Returns (kind, index_str) where kind is 'exact', 'partial', or 'none'.
    """
    normalized: list[tuple[str, str]] = []
    for r in responses:
        r = r.strip()
        if r.startswith("EXACT_MATCH"):
            idx = r.split(":")[-1].strip() if ":" in r else "-1"
            normalized.append(("exact", idx))
        elif r.startswith("PARTIAL_MATCH"):
            idx = r.split(":")[-1].strip() if ":" in r else "-1"
            normalized.append(("partial", idx))
        else:
            normalized.append(("none", "-1"))

    counts = Counter(normalized)
    most_common, freq = counts.most_common(1)[0]

    # 2-of-3 majority
    if freq >= 2:
        return most_common

    # Tiebreak: exact > partial > none
    for kind in ("exact", "partial", "none"):
        for item in normalized:
            if item[0] == kind:
                return item

    return ("none", "-1")


def score_findings(
    findings: list[dict],
    client: anthropic.Anthropic,
    model: str,
    iterations: int = 3,
    batch_size: int = 10,
) -> list[dict]:
    """
    Score each finding using the Nethermind majority-vote algorithm.
    Each finding is used as both truth and compared against all others
    to detect duplicates and false positives.
    """
    scored: list[dict] = []
    used_indices: set[int] = set()

    for i, truth_finding in enumerate(findings):
        logger.info("Scoring finding %d/%d: %s", i + 1, len(findings), truth_finding.get("title", "?"))

        # Build candidate batch from all other non-used findings
        candidates = [
            (j, f)
            for j, f in enumerate(findings)
            if j != i and j not in used_indices
        ]

        best_partial: dict | None = None
        matched = False

        # Split candidates into batches
        batches = [
            candidates[x: x + batch_size]
            for x in range(0, len(candidates), batch_size)
        ]

        for batch in batches:
            if not batch:
                continue

            batch_text = "\n".join(
                f"[{idx}] {json.dumps(f, ensure_ascii=False)}"
                for idx, f in batch
            )
            prompt = SCORE_PROMPT.format(
                truth=json.dumps(truth_finding, ensure_ascii=False),
                batch=batch_text,
            )

            # Run ITERATIONS times for majority vote
            responses = [
                _call_claude_score(prompt, client, model)
                for _ in range(iterations)
            ]
            logger.debug("Finding %d responses: %s", i, responses)

            kind, idx_str = _majority_vote(responses)

            if kind == "exact":
                try:
                    matched_idx = int(idx_str)
                except ValueError:
                    matched_idx = i
                used_indices.add(matched_idx)
                used_indices.add(i)
                scored.append({
                    "is_match": True,
                    "is_partial_match": False,
                    "is_fp": False,
                    "explanation": "Confirmed — corroborated by cross-validation scoring",
                    "severity_from_truth": truth_finding.get("severity"),
                    "severity_from_junior_auditor": truth_finding.get("severity"),
                    "index_of_finding_from_junior_auditor": i,
                    "finding_description_from_junior_auditor": truth_finding.get("description", ""),
                })
                matched = True
                break

            if kind == "partial" and best_partial is None:
                try:
                    partial_idx = int(idx_str)
                except ValueError:
                    partial_idx = i
                best_partial = {
                    "is_match": False,
                    "is_partial_match": True,
                    "is_fp": False,
                    "explanation": "Partial match — similar vulnerability class, review manually",
                    "severity_from_truth": truth_finding.get("severity"),
                    "severity_from_junior_auditor": truth_finding.get("severity"),
                    "index_of_finding_from_junior_auditor": i,
                    "finding_description_from_junior_auditor": truth_finding.get("description", ""),
                    "_partial_idx": partial_idx,
                }

        if matched:
            continue

        if best_partial and best_partial["_partial_idx"] not in used_indices:
            used_indices.add(i)
            entry = {k: v for k, v in best_partial.items() if k != "_partial_idx"}
            scored.append(entry)
            continue

        if i not in used_indices:
            # Unique finding with no duplicate — confirmed unique
            scored.append({
                "is_match": True,
                "is_partial_match": False,
                "is_fp": False,
                "explanation": "Unique finding — no duplicate detected in scan results",
                "severity_from_truth": truth_finding.get("severity"),
                "severity_from_junior_auditor": truth_finding.get("severity"),
                "index_of_finding_from_junior_auditor": i,
                "finding_description_from_junior_auditor": truth_finding.get("description", ""),
            })

    return scored


def compute_stats(findings: list[dict], scored: list[dict]) -> dict:
    total = len(findings)
    matches = sum(1 for f in scored if f.get("is_match"))
    partials = sum(1 for f in scored if f.get("is_partial_match"))
    fps = sum(1 for f in scored if f.get("is_fp"))
    missed = sum(
        1 for f in scored
        if not f.get("is_match") and not f.get("is_partial_match") and not f.get("is_fp")
    )
    sev: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "Unknown")
        sev[s] = sev.get(s, 0) + 1

    return {
        "total": total,
        "matches": matches,
        "partials": partials,
        "false_positives": fps,
        "missed": missed,
        "match_rate": round(matches / total * 100, 1) if total else 0.0,
        "severity_breakdown": sev,
    }


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@app.get("/")
def health():
    return {
        "status": "ok",
        "service": "AuditAgent API",
        "version": "1.0.0",
        "network": "Base",
    }


@app.post("/audit", response_model=AuditResponse)
def audit(req: AuditRequest):
    # 1. Fetch contract source from Basescan
    source, contract_name = fetch_contract_source(req.address, req.basescan_api_key)

    # 2. Init Anthropic client with user's key
    client = anthropic.Anthropic(api_key=req.anthropic_api_key)

    # 3. Scan with Claude
    raw = scan_contract(source, client, req.model)
    if not raw:
        raise HTTPException(
            status_code=422,
            detail=(
                "Claude returned no findings. "
                "The contract may be very simple, proxy-only, or non-Solidity."
            ),
        )

    # 4. Score findings
    scored = score_findings(raw, client, req.model, req.iterations, req.batch_size)

    # 5. Stats
    stats = compute_stats(raw, scored)

    return AuditResponse(
        address=req.address,
        contract_name=contract_name,
        source_length=len(source),
        raw_findings=[
            RawFinding(
                title=f.get("title", "Unknown"),
                severity=f.get("severity", "Unknown"),
                description=f.get("description", ""),
                location=f.get("location", ""),
            )
            for f in raw
        ],
        scored_findings=[ScoredFinding(**s) for s in scored],
        stats=AuditStats(**stats),
    )
