"""
Search Module — Multi-Mode Encrypted Search (Enhanced)
======================================================

Search modes:
  • exact    — standard keyword search (AND/OR)
  • substring — partial string matching via n-gram tokens
  • phrase   — ordered adjacent-word search via bigram tokens
  • wildcard — prefix/suffix/contains matching (*pattern, pattern*, *pattern*)
  • regex    — zero-knowledge regex: decompose pattern into literal
               fragments for server-side token matching, then verify
               with actual regex on client-side decrypted data

All modes preserve the SSE security model — the server never sees
plaintext keywords; only HMAC-derived tokens are transmitted.
"""

import re
import time
from datetime import datetime, timezone

from client.encrypt import (
    preprocess, generate_base_token, generate_randomized_token,
    generate_ngrams, generate_bigrams, MIN_NGRAM,
)
from client.regex_engine import (
    regex_to_search_fragments, verify_regex_match,
)
from server import app as server_app


# ---------------------------------------------------------------------------
# Token generation helpers
# ---------------------------------------------------------------------------

def _gen_tokens_for_keyword(keyword: str, hmac_key: bytes,
                            token_randomization_key: bytes,
                            current_counter: int) -> list:
    """Generate all randomized tokens for a keyword across all counter values."""
    base_token = generate_base_token(hmac_key, keyword)
    return [
        generate_randomized_token(token_randomization_key, base_token, c)
        for c in range(1, current_counter + 1)
    ]


def _gen_ngram_tokens(query_word: str, hmac_key: bytes,
                      token_randomization_key: bytes,
                      current_counter: int) -> list:
    """Generate n-gram tokens for a query word (substring matching)."""
    # The query word itself is the substring we're looking for
    if len(query_word) < MIN_NGRAM:
        return []

    # Generate HMAC token for this n-gram with the __ng__ prefix
    prefixed = f"__ng__{query_word}"
    base_token = generate_base_token(hmac_key, prefixed)
    return [
        generate_randomized_token(token_randomization_key, base_token, c)
        for c in range(1, current_counter + 1)
    ]


def _gen_bigram_tokens(word1: str, word2: str, hmac_key: bytes,
                       token_randomization_key: bytes,
                       current_counter: int) -> list:
    """Generate bigram tokens for an adjacent word pair (phrase matching)."""
    prefixed = f"__bg__{word1}|{word2}"
    base_token = generate_base_token(hmac_key, prefixed)
    return [
        generate_randomized_token(token_randomization_key, base_token, c)
        for c in range(1, current_counter + 1)
    ]


# ---------------------------------------------------------------------------
# Token generation for each search mode
# ---------------------------------------------------------------------------

def generate_search_tokens(
    query: str,
    hmac_key: bytes,
    token_randomization_key: bytes,
    current_counter: int,
    search_mode: str = "exact",
) -> tuple:
    """Generate search tokens based on the selected search mode.

    Modes:
        exact     — keyword tokens
        substring — n-gram tokens for partial matching
        phrase    — bigram tokens for adjacent word pairs
        wildcard  — n-gram tokens for prefix/suffix/contains
        regex     — literal fragments extracted from regex pattern

    Returns (keyword_token_lists, prep_time)
    """
    start = time.perf_counter()

    # Regex mode uses its own token generation pipeline
    if search_mode == "regex":
        keyword_token_lists = _gen_regex_tokens(
            query, hmac_key, token_randomization_key, current_counter
        )
        return keyword_token_lists, time.perf_counter() - start

    keywords = preprocess(query)

    if not keywords:
        return [], time.perf_counter() - start

    keyword_token_lists = []

    if search_mode == "exact":
        for keyword in keywords:
            tokens = _gen_tokens_for_keyword(
                keyword, hmac_key, token_randomization_key, current_counter
            )
            keyword_token_lists.append(tokens)

    elif search_mode == "substring":
        for keyword in keywords:
            tokens = _gen_ngram_tokens(
                keyword, hmac_key, token_randomization_key, current_counter
            )
            if tokens:
                keyword_token_lists.append(tokens)

    elif search_mode == "phrase":
        if len(keywords) >= 2:
            for i in range(len(keywords) - 1):
                tokens = _gen_bigram_tokens(
                    keywords[i], keywords[i + 1],
                    hmac_key, token_randomization_key, current_counter
                )
                keyword_token_lists.append(tokens)
        else:
            for keyword in keywords:
                tokens = _gen_tokens_for_keyword(
                    keyword, hmac_key, token_randomization_key, current_counter
                )
                keyword_token_lists.append(tokens)

    elif search_mode == "wildcard":
        raw = query.lower().strip().strip("*").strip()
        if raw and len(raw) >= MIN_NGRAM:
            tokens = _gen_ngram_tokens(
                raw, hmac_key, token_randomization_key, current_counter
            )
            if tokens:
                keyword_token_lists.append(tokens)
        elif raw:
            tokens = _gen_tokens_for_keyword(
                raw, hmac_key, token_randomization_key, current_counter
            )
            keyword_token_lists.append(tokens)

    prep_time = time.perf_counter() - start
    return keyword_token_lists, prep_time


def _gen_regex_tokens(pattern: str, hmac_key: bytes,
                      token_randomization_key: bytes,
                      current_counter: int) -> list:
    """Generate search tokens from regex literal fragments.

    Phase 1 of zero-knowledge regex: extract fixed substrings from
    the pattern and generate HMAC tokens for n-gram matching.
    """
    analysis = regex_to_search_fragments(pattern)
    fragments = analysis["fragments"]

    if not fragments:
        return []

    token_lists = []
    for frag in fragments:
        text = frag["text"].lower()
        if len(text) < MIN_NGRAM:
            continue

        # Try exact keyword token first
        exact_tokens = _gen_tokens_for_keyword(
            text, hmac_key, token_randomization_key, current_counter
        )

        # Also generate n-gram tokens for substring matching
        ngram_tokens = _gen_ngram_tokens(
            text, hmac_key, token_randomization_key, current_counter
        )

        # Combine both: exact match + substring match
        combined = exact_tokens + (ngram_tokens if ngram_tokens else [])
        if combined:
            token_lists.append(combined)

    return token_lists


# ---------------------------------------------------------------------------
# Main search function (enhanced)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Query Parsing & Boolean Logic
# ---------------------------------------------------------------------------

def parse_query(query: str, default_mode: str = "OR") -> tuple:
    """Parse query string into positive and negative terms.
    
    Syntax:
      - term      : default mode (OR/AND)
      - +term     : MUST include (AND) - currently treated as positive
      - -term     : MUST NOT include (NOT)
      
    Returns: (positive_terms, negative_terms)
    """
    positive_terms = []
    negative_terms = []
    
    # Split by whitespace but respect quotes (simple splitting for now)
    # TODO: Add proper quote handling for phrases if needed
    tokens = query.strip().split()
    
    for token in tokens:
        if token.startswith('-') and len(token) > 1:
            negative_terms.append(token[1:])
        elif token.startswith('+') and len(token) > 1:
            positive_terms.append(token[1:])
        else:
            positive_terms.append(token)
            
    return positive_terms, negative_terms


# ---------------------------------------------------------------------------
# Main search function (enhanced)
# ---------------------------------------------------------------------------

def search(
    query: str,
    hmac_key: bytes,
    token_randomization_key: bytes,
    mode: str = "OR",  # Default to OR for better UX
    known_file_ids: set = None,
    search_mode: str = "exact",
    file_encryption_key: bytes = None,
) -> dict:
    """End-to-end client search with Boolean logic and ranking.

    Args:
        query:  Raw search string (or regex pattern).
        mode:   Default logical operator ("AND" or "OR") for positive terms.
        ...
    """
    if known_file_ids is None:
        known_file_ids = set()

    current_counter = server_app.get_counter()
    start_total = time.perf_counter()

    # Regex mode bypasses standard parsing
    if search_mode == "regex":
        # ... (keep existing regex logic or wrap it)
        # For now, simplistic handling: regex doesn't support +/- syntax easily
        pass 
    
    # Step 0 - Parse Query
    positive_terms, negative_terms = parse_query(query, mode)
    
    if not positive_terms and not negative_terms:
         return {
            "real_file_ids": [], "all_file_ids": [], "ranked_results": [],
            "search_time": 0, "token_gen_time": 0,
            "search_mode": search_mode, "regex_matches": {},
        }

    # Step 1 — generate tokens (Positives)
    # We join positive terms back into a string to use existing generation logic per term
    # This is a bit inefficient but reuses the n-gram/phrase logic
    pos_token_lists = []
    token_gen_start = time.perf_counter()
    
    for term in positive_terms:
        tls, _ = generate_search_tokens(
            term, hmac_key, token_randomization_key,
            current_counter, search_mode
        )
        pos_token_lists.extend(tls)

    # Step 1b - generate tokens (Negatives)
    neg_token_lists = []
    for term in negative_terms:
        # For negatives, we usually just need exact or substring match
        # Enforce 'exact' or same as search_mode? Let's use search_mode for consistency
        tls, _ = generate_search_tokens(
            term, hmac_key, token_randomization_key,
            current_counter, search_mode
        )
        neg_token_lists.extend(tls)
        
    token_gen_time = time.perf_counter() - token_gen_start

    if not pos_token_lists:
        # If only negatives, we can't search (SSE limitation: can't return "everything except X")
        return {
            "real_file_ids": [], "all_file_ids": [], "ranked_results": [],
            "search_time": 0, "token_gen_time": token_gen_time,
            "search_mode": search_mode, "regex_matches": {},
        }

    # Step 2 — Query Server (Positives)
    # We use search_ranked to get TF-IDF scores
    server_search_start = time.perf_counter()
    ranked_results = server_app.search_ranked(pos_token_lists, mode)
    all_positive_ids = {r['file_id'] for r in ranked_results}
    
    # Step 3 - Query Server (Negatives) - Unranked is sufficient
    excluded_ids = set()
    if neg_token_lists:
        # Mode OR because if it matches ANY negative term, we exclude it
        excluded_ids = set(server_app.search(neg_token_lists, mode="OR"))
    
    server_time = time.perf_counter() - server_search_start

    # Step 4 — Filter Results (Boolean NOT)
    final_ids = all_positive_ids - excluded_ids
    
    # Filter dummy IDs
    real_file_ids = [fid for fid in final_ids if fid in known_file_ids]
    
    # Filter ranked results
    real_ranked = [
        r for r in ranked_results 
        if r["file_id"] in real_file_ids
    ]
    
    # Step 5 — Regex Verification (Phase 2)
    regex_matches = {}
    if search_mode == "regex" and file_encryption_key and real_file_ids:
        from client.decrypt import decrypt_file as _df
        try:
            analysis = regex_to_search_fragments(query)
            compiled = analysis["compiled"]
            verified_ids = []
            verified_ranked = []
            for fid in real_file_ids:
                try:
                    plaintext = _df(fid, file_encryption_key).decode("utf-8", errors="replace")
                    matches = verify_regex_match(compiled, plaintext)
                    if matches:
                        regex_matches[fid] = matches
                        verified_ids.append(fid)
                except Exception:
                    pass
            real_file_ids = verified_ids
            real_ranked = [r for r in real_ranked if r["file_id"] in set(verified_ids)]
        except:
             pass

    total_time = time.perf_counter() - start_total

    # Step 6 — Analytics
    num_tokens = sum(len(tl) for tl in pos_token_lists + neg_token_lists)
    server_app.record_search(mode, num_tokens, len(real_file_ids),
                             total_time * 1000, search_mode)

    return {
        "real_file_ids": real_file_ids,
        "all_file_ids": list(all_positive_ids), # Return unfiltered positives as 'all'
        "ranked_results": real_ranked,
        "search_time": total_time,
        "token_gen_time": token_gen_time,
        "search_mode": search_mode,
        "regex_matches": regex_matches,
    }
