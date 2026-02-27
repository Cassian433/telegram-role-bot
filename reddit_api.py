"""
Reddit public JSON API wrapper — async, rate-limited, no auth required.
"""

import asyncio
import re
import logging
from datetime import datetime, timezone, timedelta
from collections import Counter

import httpx

logger = logging.getLogger(__name__)

USER_AGENT = "RedditScraperBot/1.0 (Telegram bot; subreddit research)"
REQUEST_DELAY = 2  # seconds between requests
TIMEOUT = 15

# ── Shared HTTP client ────────────────────────────────────────────────────────

_last_request_time = 0.0


async def _throttle():
    """Enforce minimum delay between Reddit requests."""
    global _last_request_time
    now = asyncio.get_event_loop().time()
    wait = REQUEST_DELAY - (now - _last_request_time)
    if wait > 0:
        await asyncio.sleep(wait)
    _last_request_time = asyncio.get_event_loop().time()


async def _get(url: str, params: dict = None, retries: int = 2) -> dict | None:
    """GET a Reddit JSON endpoint with throttling and retry."""
    headers = {"User-Agent": USER_AGENT}
    for attempt in range(retries + 1):
        await _throttle()
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    url, headers=headers, params=params,
                    follow_redirects=True, timeout=TIMEOUT,
                )
                if resp.status_code == 429:
                    logger.warning("Reddit 429 — backing off 30s")
                    await asyncio.sleep(30)
                    continue
                if resp.status_code in (403, 404):
                    return {"_error": resp.status_code}
                if resp.status_code != 200:
                    return None
                return resp.json()
        except Exception as e:
            logger.error(f"Reddit request error ({url}): {e}")
            if attempt < retries:
                await asyncio.sleep(5)
    return None


def _fmt_number(n: int) -> str:
    """Format large numbers: 1500 -> 1.5k, 2300000 -> 2.3M"""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}k"
    return str(n)


def _time_ago(utc_ts: float) -> str:
    """Convert UTC timestamp to '3h ago' style string."""
    if not utc_ts:
        return "?"
    delta = datetime.now(timezone.utc) - datetime.fromtimestamp(utc_ts, tz=timezone.utc)
    secs = int(delta.total_seconds())
    if secs < 60:
        return f"{secs}s ago"
    if secs < 3600:
        return f"{secs // 60}m ago"
    if secs < 86400:
        return f"{secs // 3600}h ago"
    return f"{secs // 86400}d ago"


def _age_str(created_utc: float) -> str:
    """Convert created_utc to human-readable age."""
    if not created_utc:
        return "?"
    dt = datetime.fromtimestamp(created_utc, tz=timezone.utc)
    days = (datetime.now(timezone.utc) - dt).days
    if days >= 365:
        return f"{days // 365}y {(days % 365) // 30}m"
    if days >= 30:
        return f"{days // 30}m {days % 30}d"
    return f"{days}d"


# ── Subreddit functions ───────────────────────────────────────────────────────


async def fetch_subreddit_info(sub: str) -> dict | None:
    """Fetch subreddit metadata (subscribers, description, NSFW, etc.)."""
    data = await _get(f"https://www.reddit.com/r/{sub}/about.json")
    if not data or "_error" in data:
        return data
    d = data.get("data", {})
    return {
        "name": d.get("display_name", sub),
        "title": d.get("title", ""),
        "description": d.get("public_description", ""),
        "full_description": d.get("description", ""),
        "subscribers": d.get("subscribers", 0),
        "active_users": d.get("accounts_active", 0),
        "nsfw": d.get("over18", False),
        "created_utc": d.get("created_utc", 0),
        "submission_type": d.get("submission_type", "any"),
        "allow_images": d.get("allow_images", True),
        "allow_videos": d.get("allow_videogifs", True),
    }


async def fetch_posts(sub: str, sort: str = "hot", time: str = "day", limit: int = 25) -> list:
    """Fetch posts from a subreddit. sort: hot/top/new/rising. time: hour/day/week/month/year/all."""
    params = {"limit": min(limit, 100)}
    if sort == "top":
        params["t"] = time
    data = await _get(f"https://www.reddit.com/r/{sub}/{sort}.json", params)
    if not data or "_error" in data:
        return []

    posts = []
    for child in data.get("data", {}).get("children", []):
        p = child.get("data", {})
        posts.append({
            "title": p.get("title", ""),
            "score": p.get("score", 0),
            "comments": p.get("num_comments", 0),
            "author": p.get("author", "[deleted]"),
            "created_utc": p.get("created_utc", 0),
            "url": f"https://reddit.com{p.get('permalink', '')}",
            "flair": p.get("link_flair_text", ""),
            "nsfw": p.get("over_18", False),
            "upvote_ratio": p.get("upvote_ratio", 0),
        })
    return posts


async def fetch_subreddit_rules(sub: str) -> list:
    """Fetch subreddit rules."""
    data = await _get(f"https://www.reddit.com/r/{sub}/about/rules.json")
    if not data or "_error" in data:
        return []
    rules = []
    for r in data.get("rules", []):
        rules.append({
            "title": r.get("short_name", ""),
            "description": r.get("description", ""),
            "kind": r.get("kind", "all"),
        })
    return rules


async def analyze_sub_floor(sub: str, hours_back: int = 3, max_posts: int = 50) -> dict:
    """
    Find the REAL posting floor by scanning actual posts.
    Finds the lowest karma account and newest account that successfully posted.
    """
    posts = await fetch_posts(sub, sort="new", limit=max_posts)
    if not posts:
        return {}

    cutoff = datetime.now(timezone.utc).timestamp() - (hours_back * 3600)
    # Filter to recent posts only
    recent = [p for p in posts if p["created_utc"] >= cutoff]
    if not recent:
        # Fall back to whatever we got
        recent = posts[:25]

    lowest_karma_user = None
    newest_user = None
    users_checked = 0
    activity_count = len(recent)

    seen = set()
    for p in recent:
        author = p["author"]
        if author in ("[deleted]", "AutoModerator", "[removed]") or author in seen:
            continue
        seen.add(author)

        profile = await fetch_user_profile(author)
        if not profile or profile.get("suspended"):
            continue
        users_checked += 1

        user_data = {
            "username": profile["username"],
            "total_karma": profile["total_karma"],
            "post_karma": profile["post_karma"],
            "comment_karma": profile["comment_karma"],
            "age": profile["age"],
            "created_date": profile["created_date"],
            "created_utc": profile["created_utc"],
            "post_title": p["title"][:60],
            "post_url": p.get("url", ""),
        }

        # Track lowest karma
        if lowest_karma_user is None or profile["total_karma"] < lowest_karma_user["total_karma"]:
            lowest_karma_user = user_data

        # Track newest account
        if newest_user is None or profile["created_utc"] > newest_user["created_utc"]:
            newest_user = user_data

    # Calculate subreddit age and activity
    info = await fetch_subreddit_info(sub)
    sub_age_days = None
    subscribers = 0
    if info and "_error" not in info:
        if info.get("created_utc"):
            sub_age_days = (datetime.now(timezone.utc) - datetime.fromtimestamp(info["created_utc"], tz=timezone.utc)).days
        subscribers = info.get("subscribers", 0)

    # Activity level
    posts_per_day = activity_count * (24 / max(hours_back, 1))
    if posts_per_day >= 50:
        activity_level = "VERY ACTIVE"
    elif posts_per_day >= 20:
        activity_level = "ACTIVE"
    elif posts_per_day >= 5:
        activity_level = "MODERATE"
    else:
        activity_level = "LOW"

    return {
        "subscribers": subscribers,
        "sub_age_days": sub_age_days,
        "activity_level": activity_level,
        "posts_per_day": round(posts_per_day),
        "posts_sampled": activity_count,
        "users_checked": users_checked,
        "hours_back": hours_back,
        "lowest_karma": lowest_karma_user,
        "newest_account": newest_user,
        "nsfw": info.get("nsfw", False) if info and "_error" not in info else False,
    }


async def detect_requirements(sub: str) -> dict:
    """
    Detect posting requirements by parsing rules, sidebar, and automod.
    Returns structured dict of detected requirements.
    """
    reqs = {
        "min_karma": None,
        "min_comment_karma": None,
        "min_post_karma": None,
        "min_age_days": None,
        "verification": False,
        "flair_required": False,
        "flair_options": [],
        "posting_frequency": None,
        "key_rules": [],
        "raw_rules_count": 0,
    }

    # 1. Fetch subreddit info (sidebar/description)
    info = await fetch_subreddit_info(sub)
    if not info or isinstance(info, dict) and info.get("_error"):
        return reqs

    # 2. Fetch rules
    rules = await fetch_subreddit_rules(sub)
    reqs["raw_rules_count"] = len(rules)

    # Combine all text sources for scanning
    text_sources = [
        info.get("description", ""),
        info.get("full_description", ""),
    ]
    for r in rules:
        text_sources.append(r.get("title", ""))
        text_sources.append(r.get("description", ""))
        # Save important rules
        title = r.get("title", "").strip()
        if title:
            reqs["key_rules"].append(title)

    all_text = "\n".join(text_sources).lower()

    # 3. Try automod wiki (usually 403 but worth a shot)
    automod = await _get(f"https://www.reddit.com/r/{sub}/wiki/config/automoderator.json")
    if automod and "_error" not in automod:
        wiki_content = automod.get("data", {}).get("content_md", "")
        if wiki_content:
            all_text += "\n" + wiki_content.lower()

    # 4. Parse with regex patterns
    # Karma patterns
    karma_patterns = [
        r"(?:minimum|min|at\s*least|need|require)\s*(\d+)\s*(?:combined\s*)?karma",
        r"(\d+)\s*(?:combined\s*)?karma\s*(?:minimum|required|needed|to\s*post)",
        r"karma.*?(?:at\s*least|minimum|min)\s*(\d+)",
        r"(\d+)\s*karma\s*(?:or\s*more|threshold)",
    ]
    for pat in karma_patterns:
        m = re.search(pat, all_text)
        if m:
            reqs["min_karma"] = int(m.group(1))
            break

    # Comment karma specifically
    ck_patterns = [
        r"(\d+)\s*comment\s*karma",
        r"comment\s*karma.*?(\d+)",
    ]
    for pat in ck_patterns:
        m = re.search(pat, all_text)
        if m:
            reqs["min_comment_karma"] = int(m.group(1))
            break

    # Post karma specifically
    pk_patterns = [
        r"(\d+)\s*(?:post|link)\s*karma",
        r"(?:post|link)\s*karma.*?(\d+)",
    ]
    for pat in pk_patterns:
        m = re.search(pat, all_text)
        if m:
            reqs["min_post_karma"] = int(m.group(1))
            break

    # Account age patterns
    age_patterns = [
        r"(?:account|acc).*?(?:at\s*least|minimum|min|older\s*than)\s*(\d+)\s*day",
        r"(\d+)\s*day(?:s)?\s*(?:old|account\s*age|minimum)",
        r"(?:minimum|min)\s*(?:account\s*)?age.*?(\d+)\s*day",
        r"(\d+)\s*day\s*(?:old\s*)?account",
        # Weeks/months
        r"(\d+)\s*week(?:s)?\s*(?:old|account)",
        r"(\d+)\s*month(?:s)?\s*(?:old|account)",
    ]
    for i, pat in enumerate(age_patterns):
        m = re.search(pat, all_text)
        if m:
            val = int(m.group(1))
            if i >= 4:  # weeks pattern
                val *= 7
            if i >= 5:  # months pattern
                val = val * 30 // 7  # undo week multiply, apply month
                val = int(m.group(1)) * 30
            reqs["min_age_days"] = val
            break

    # Verification
    if any(w in all_text for w in ["verification", "verified", "verify yourself", "must verify"]):
        reqs["verification"] = True

    # Flair
    if any(w in all_text for w in ["flair required", "must flair", "use flair", "post flair"]):
        reqs["flair_required"] = True

    # Posting frequency
    freq_patterns = [
        r"(\d+)\s*post(?:s)?\s*(?:per|every|\/)\s*(\d+)?\s*(hour|day|week)",
        r"(?:once|one\s*post)\s*(?:per|every|\/)\s*(\d+)?\s*(hour|day|week)",
        r"wait\s*(\d+)\s*(hour|day|minute)",
    ]
    for pat in freq_patterns:
        m = re.search(pat, all_text)
        if m:
            reqs["posting_frequency"] = m.group(0).strip()
            break

    return reqs


# ── User profile functions ────────────────────────────────────────────────────


async def fetch_user_profile(username: str) -> dict | None:
    """Fetch Reddit user profile."""
    data = await _get(f"https://www.reddit.com/user/{username}/about.json")
    if not data:
        return None
    if "_error" in data:
        return {"suspended": True, "username": username}

    d = data.get("data", {})
    if d.get("is_suspended"):
        return {"suspended": True, "username": username}

    created_utc = d.get("created_utc", 0)
    return {
        "username": d.get("name", username),
        "post_karma": d.get("link_karma", 0),
        "comment_karma": d.get("comment_karma", 0),
        "total_karma": d.get("link_karma", 0) + d.get("comment_karma", 0),
        "created_utc": created_utc,
        "age": _age_str(created_utc),
        "created_date": datetime.fromtimestamp(created_utc, tz=timezone.utc).strftime("%Y-%m-%d") if created_utc else "?",
        "nsfw": d.get("subreddit", {}).get("over_18", False),
        "suspended": False,
    }


async def fetch_user_posts(username: str, limit: int = 100) -> list:
    """Fetch a user's submitted posts."""
    posts = []
    after = None
    remaining = limit

    while remaining > 0:
        batch = min(remaining, 100)
        params = {"limit": batch}
        if after:
            params["after"] = after

        data = await _get(f"https://www.reddit.com/user/{username}/submitted.json", params)
        if not data or "_error" in data:
            break

        children = data.get("data", {}).get("children", [])
        if not children:
            break

        for child in children:
            p = child.get("data", {})
            posts.append({
                "subreddit": p.get("subreddit", "?"),
                "title": p.get("title", ""),
                "score": p.get("score", 0),
                "comments": p.get("num_comments", 0),
                "created_utc": p.get("created_utc", 0),
                "nsfw": p.get("over_18", False),
                "url": f"https://reddit.com{p.get('permalink', '')}",
            })

        after = data.get("data", {}).get("after")
        if not after:
            break
        remaining -= len(children)

    return posts


async def fetch_user_comments(username: str, limit: int = 100) -> list:
    """Fetch a user's comments."""
    params = {"limit": min(limit, 100)}
    data = await _get(f"https://www.reddit.com/user/{username}/comments.json", params)
    if not data or "_error" in data:
        return []

    comments = []
    for child in data.get("data", {}).get("children", []):
        c = child.get("data", {})
        comments.append({
            "subreddit": c.get("subreddit", "?"),
            "body": c.get("body", "")[:100],
            "score": c.get("score", 0),
            "created_utc": c.get("created_utc", 0),
        })
    return comments


# ── Search & discovery ────────────────────────────────────────────────────────


async def search_subreddits(query: str, nsfw: bool = False, limit: int = 20) -> list:
    """Search for subreddits by keyword."""
    params = {
        "q": query,
        "limit": min(limit, 50),
        "include_over_18": "true" if nsfw else "false",
    }
    # Use the search endpoint
    data = await _get("https://www.reddit.com/subreddits/search.json", params)
    if not data or "_error" in data:
        return []

    results = []
    for child in data.get("data", {}).get("children", []):
        s = child.get("data", {})
        results.append({
            "name": s.get("display_name", ""),
            "subscribers": s.get("subscribers", 0),
            "active": s.get("accounts_active", 0),
            "nsfw": s.get("over18", False),
            "description": (s.get("public_description", "") or "")[:120],
            "created_utc": s.get("created_utc", 0),
        })

    # Sort by subscribers descending
    results.sort(key=lambda x: x["subscribers"], reverse=True)
    return results


async def find_similar_subs(sub: str, sample_size: int = 25) -> list:
    """
    Find similar subreddits by analyzing user overlap.
    Fetches recent posters from the sub, then checks where else they post.
    """
    # Step 1: Get recent posts to find active users
    posts = await fetch_posts(sub, sort="hot", limit=50)
    if not posts:
        posts = await fetch_posts(sub, sort="new", limit=50)
    if not posts:
        return []

    # Collect unique authors (skip bots and deleted)
    authors = []
    seen = set()
    for p in posts:
        author = p["author"]
        if author in ("[deleted]", "AutoModerator") or author in seen:
            continue
        seen.add(author)
        authors.append(author)
        if len(authors) >= sample_size:
            break

    # Step 2: For each user, check their recent post history
    sub_counts = Counter()
    users_checked = 0
    source_lower = sub.lower()

    for author in authors:
        user_posts = await fetch_user_posts(author, limit=50)
        if not user_posts:
            continue
        users_checked += 1

        user_subs = set()
        for p in user_posts:
            s = p["subreddit"]
            if s.lower() != source_lower:
                user_subs.add(s)
        for s in user_subs:
            sub_counts[s] += 1

    if users_checked == 0:
        return []

    # Step 3: Rank by overlap percentage
    results = []
    for sub_name, count in sub_counts.most_common(30):
        overlap_pct = round(count / users_checked * 100)
        if overlap_pct < 5:
            continue

        # Fetch sub info for subscriber count
        info = await fetch_subreddit_info(sub_name)
        subs_count = 0
        is_nsfw = False
        if info and "_error" not in info:
            subs_count = info.get("subscribers", 0)
            is_nsfw = info.get("nsfw", False)

        results.append({
            "name": sub_name,
            "overlap_pct": overlap_pct,
            "subscribers": subs_count,
            "nsfw": is_nsfw,
        })

        # Don't fetch info for too many subs (rate limiting)
        if len(results) >= 15:
            break

    return results
