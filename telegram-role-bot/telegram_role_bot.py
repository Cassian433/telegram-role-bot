import asyncio
import json
import os
import re
import logging
import traceback
from html import escape as esc
from datetime import datetime, timezone, timedelta
from collections import Counter, defaultdict

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)
from telegram.constants import ParseMode
from pyairtable import Api
import httpx
import reddit_api as reddit

# ── Configuration ──────────────────────────────────────────────────────────────

BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
AIRTABLE_TOKEN = os.environ.get("AIRTABLE_TOKEN", "").strip()
AIRTABLE_BASE_ID = os.environ.get("AIRTABLE_BASE_ID", "appgfF7RfD37gL1PF").strip()

# Airtable table IDs
TABLE_TELEGRAM = "tblnV0XKKrrHTCZBD"
TABLE_VAS = "tbl5Xn3w2DfYZdjic"
TABLE_CAPTIONS = "tblKSMX7DZrV72O9J"
TABLE_EMAILS = "tblEBTyCnh5hfm4L7"
TABLE_BLANKS = "tblqZmGp599y0cfMN"
TABLE_WARMUP = "tblRiuhzNT9eLINqR"
TABLE_POSTING = "tblypMJHC0DqQ4cF8"
TABLE_POSTING_LOGS = "tbl7Em1dzfol97Za9"

# Local data files
DATA_DIR = os.path.dirname(os.path.abspath(__file__))
ROLES_FILE = os.path.join(DATA_DIR, "roles_data.json")
CONFIG_FILE = os.path.join(DATA_DIR, "bot_config.json")

# Ban polling interval in seconds
BAN_POLL_INTERVAL = 180  # 3 minutes
POST_LOG_FLUSH_INTERVAL = 10800  # 3 hours in seconds

# Pending post log entries: {(chat_id, thread_id): [(va_name, model, result_line), ...]}
_pending_post_logs: dict[tuple[str, int], list[tuple[str, str, str]]] = defaultdict(list)

REDDIT_URL_PATTERN = re.compile(
    r"https?://(?:www\.|old\.)?reddit\.com/(?:r/\w+/(?:comments|s)/\S+|user?/\w+\S*)",
    re.IGNORECASE,
)
REDDIT_USER_FROM_POST = re.compile(
    r"reddit\.com/r/\w+/comments/\w+/\w+", re.IGNORECASE
)
REDDIT_USER_PROFILE = re.compile(
    r"reddit\.com/u(?:ser)?/(\w+)", re.IGNORECASE
)

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# ── Airtable helpers ───────────────────────────────────────────────────────────

_api = None


def get_api():
    global _api
    if _api is None:
        _api = Api(AIRTABLE_TOKEN)
    return _api


def get_table(table_id):
    return get_api().table(AIRTABLE_BASE_ID, table_id)


def safe_get(record, field, default=""):
    """Safely get a field value from an Airtable record."""
    return record.get("fields", {}).get(field, default)


def count_by_field(records, field):
    """Count records grouped by a field value."""
    counts = Counter()
    for r in records:
        val = safe_get(r, field, "Unknown")
        if isinstance(val, list):
            for v in val:
                counts[v] += 1
        else:
            counts[val] += 1
    return counts


# ── Bot config helpers (topics, ban channel, VA mapping) ──────────────────────

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {"topics": {}, "ban_channel": None, "va_map": {}, "known_bans": []}


def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def get_topic_config(chat_id, thread_id):
    """Get VA and Model for a configured topic."""
    cfg = load_config()
    key = f"{chat_id}:{thread_id}"
    return cfg.get("topics", {}).get(key)


# ── Role management helpers (preserved from original) ─────────────────────────

def load_roles_data():
    if os.path.exists(ROLES_FILE):
        with open(ROLES_FILE, "r") as f:
            return json.load(f)
    return {}


def save_roles_data(data):
    with open(ROLES_FILE, "w") as f:
        json.dump(data, f, indent=2)


def get_chat_data(chat_id: str):
    data = load_roles_data()
    if chat_id not in data:
        data[chat_id] = {"roles": [], "assignments": {}}
        save_roles_data(data)
    return data, data[chat_id]


# ── Generic helpers ───────────────────────────────────────────────────────────

async def reply(update: Update, text: str, parse_mode=None, **extra):
    try:
        return await update.message.reply_text(text, parse_mode=parse_mode, **extra)
    except Exception as e1:
        logger.warning(f"reply_text failed ({e1}), falling back to send_message")
        try:
            kw = {"chat_id": update.effective_chat.id, "text": text, **extra}
            if parse_mode:
                kw["parse_mode"] = parse_mode
            if update.message and update.message.message_thread_id:
                kw["message_thread_id"] = update.message.message_thread_id
            return await update.get_bot().send_message(**kw)
        except Exception as e2:
            logger.error(f"Failed to send message: {e2}")


async def is_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if update.effective_chat.type == "private":
        return True
    try:
        member = await context.bot.get_chat_member(
            update.effective_chat.id, update.effective_user.id
        )
        return member.status in ("administrator", "creator")
    except Exception:
        return False


# Cache of username -> (user_id, display_name) built from group activity
_username_cache: dict[str, tuple[int, str]] = {}


def _cache_user(user):
    """Cache a Telegram user's username -> id mapping."""
    if user and user.username:
        _username_cache[user.username.lower()] = (user.id, user.first_name or "User")


def extract_user_ids_from_message(update: Update):
    users = []
    seen = set()

    # Cache the sender
    if update.message.from_user:
        _cache_user(update.message.from_user)

    # 1. Reply — grab the replied-to user
    if update.message.reply_to_message and update.message.reply_to_message.from_user:
        u = update.message.reply_to_message.from_user
        _cache_user(u)
        if u.id not in seen:
            seen.add(u.id)
            users.append((u.id, u.first_name or "User"))

    # 2. Entities — text_mention (has user object) and mention (@username)
    for ent in update.message.entities or []:
        if ent.type == "text_mention" and ent.user:
            _cache_user(ent.user)
            if ent.user.id not in seen:
                seen.add(ent.user.id)
                users.append((ent.user.id, ent.user.first_name or "User"))
        elif ent.type == "mention":
            # @username mention — extract the username text (strip the @)
            raw = update.message.text[ent.offset:ent.offset + ent.length]
            uname = raw.lstrip("@").lower()
            cached = _username_cache.get(uname)
            if cached and cached[0] not in seen:
                seen.add(cached[0])
                users.append(cached)

    return users


IST = timezone(timedelta(hours=5, minutes=30))


def now_utc():
    return datetime.now(timezone.utc)


def now_ist():
    return datetime.now(IST)


def to_ist(dt):
    """Convert a UTC datetime to IST."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST)


def start_of_today_ist():
    """Midnight IST today."""
    n = now_ist()
    return n.replace(hour=0, minute=0, second=0, microsecond=0)


def start_of_today():
    n = now_utc()
    return n.replace(hour=0, minute=0, second=0, microsecond=0)


def start_of_week():
    n = now_utc()
    return (n - timedelta(days=n.weekday())).replace(
        hour=0, minute=0, second=0, microsecond=0
    )


def ist_fmt(dt):
    """Format a datetime as IST time string."""
    if dt is None:
        return "N/A"
    return to_ist(dt).strftime("%I:%M %p IST")


def parse_date_loose(val):
    """Try to parse a date string in various formats."""
    if not val:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d", "%m/%d/%Y", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(val, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


# ── VA record ID → name cache ────────────────────────────────────────────────
# The "Created By" (createdBy) field in Posting Logs always shows "Rakshit"
# because all VAs share one Airtable account. We use the "VAs" linked record
# field instead and resolve record IDs to VA names via this cache.

_va_name_cache = {}
_va_cache_ts = None  # UTC timestamp of last cache build


def _ensure_va_cache(max_age_sec=300):
    """Build or refresh the VA record ID → name mapping (cached 5 min)."""
    global _va_name_cache, _va_cache_ts
    now = datetime.now(timezone.utc)
    if _va_cache_ts and (now - _va_cache_ts).total_seconds() < max_age_sec:
        return _va_name_cache
    try:
        vas = get_table(TABLE_VAS).all()
        _va_name_cache = {v["id"]: safe_get(v, "VA Name", "Unknown") for v in vas}
        _va_cache_ts = now
    except Exception as e:
        logger.error(f"VA cache build failed: {e}")
    return _va_name_cache


def _get_log_va_name(record):
    """Extract VA name from a Posting Logs record via VAs linked field."""
    va_ids = safe_get(record, "VAs", [])
    if isinstance(va_ids, list) and va_ids:
        cache = _ensure_va_cache()
        # Return first linked VA name
        for vid in va_ids:
            name = cache.get(vid)
            if name:
                return name
    # Fallback: shouldn't happen for new records, but covers old data
    return "Unknown"


# ── Reddit profile scraper ───────────────────────────────────────────────────

REDDIT_USER_AGENT = "RedditOpsBot/1.0 (Telegram bot; account monitoring)"
ACCOUNT_UPDATE_INTERVAL = 21600  # 6 hours in seconds


async def fetch_reddit_profile(username):
    """Fetch Reddit user profile data via public JSON API."""
    url = f"https://www.reddit.com/user/{username}/about.json"
    headers = {"User-Agent": REDDIT_USER_AGENT}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers, follow_redirects=True, timeout=15)
            if resp.status_code in (404, 403):
                return {"suspended": True}
            if resp.status_code == 429:
                return {"rate_limited": True}
            if resp.status_code != 200:
                return None
            data = resp.json().get("data", {})

            if data.get("is_suspended"):
                return {"suspended": True}

            created_utc = data.get("created_utc", 0)
            created_dt = datetime.fromtimestamp(created_utc, tz=timezone.utc) if created_utc else None

            # Calculate account age as human-readable string
            age_str = None
            if created_dt:
                age_delta = datetime.now(timezone.utc) - created_dt
                days = age_delta.days
                if days >= 365:
                    age_str = f"{days // 365}y {(days % 365) // 30}m"
                elif days >= 30:
                    age_str = f"{days // 30}m {days % 30}d"
                else:
                    age_str = f"{days}d"

            return {
                "post_karma": str(data.get("link_karma", 0)),
                "comment_karma": str(data.get("comment_karma", 0)),
                "total_karma": data.get("link_karma", 0) + data.get("comment_karma", 0),
                "account_age": age_str,
                "date_of_creation": created_dt.strftime("%Y-%m-%d") if created_dt else None,
                "suspended": False,
                "rate_limited": False,
            }
    except Exception as e:
        logger.error(f"Reddit profile fetch error for u/{username}: {e}")
        return None


async def update_account_info_job(context: ContextTypes.DEFAULT_TYPE):
    """Scheduled job: update karma, age, DOC for all active posting accounts."""
    logger.info("Starting scheduled account info update...")
    cfg = load_config()
    is_first_refresh = not cfg.get("refresh_seeded", False)
    try:
        posting = get_table(TABLE_POSTING).all()
        active = [r for r in posting if safe_get(r, "Status") in ("Posting", "Dormant")]
        logger.info(f"Updating {len(active)} active/dormant accounts...")

        SCHED_BATCH = 5
        SCHED_BATCH_PAUSE = 30
        SCHED_REQ_DELAY = 5
        SCHED_RATE_LIMIT_PAUSE = 120

        updated = 0
        suspended_list = []  # track newly found suspensions
        errors = 0

        for i, r in enumerate(active):
            username = safe_get(r, "Reddit Username", "").strip()
            if not username:
                continue

            # Batch pause
            if i > 0 and i % SCHED_BATCH == 0:
                logger.info(f"Posting ban check: {i}/{len(active)} done, pausing {SCHED_BATCH_PAUSE}s...")
                await asyncio.sleep(SCHED_BATCH_PAUSE)

            profile = await fetch_reddit_profile(username)
            if not profile:
                errors += 1
                await asyncio.sleep(SCHED_REQ_DELAY)
                continue

            if profile.get("rate_limited"):
                logger.warning(f"Reddit rate limited, pausing {SCHED_RATE_LIMIT_PAUSE}s...")
                await asyncio.sleep(SCHED_RATE_LIMIT_PAUSE)
                profile = await fetch_reddit_profile(username)
                if not profile or profile.get("rate_limited"):
                    errors += 1
                    continue

            if profile.get("suspended"):
                va = safe_get(r, "VA", "N/A")
                model = safe_get(r, "Model", "N/A")
                current_status = safe_get(r, "Status")
                if current_status == "Posting":
                    try:
                        get_table(TABLE_POSTING).update(r["id"], {"Status": "Banned"})
                    except Exception:
                        pass
                    proxy = safe_get(r, "Proxy Used", "").strip()
                    proxy_tag = f"🔒 {proxy}" if proxy else "⚠️ Proxy not mentioned"
                    suspended_list.append(f"u/{username} ({va} / {model})\n      📍 Posting | {proxy_tag}")
                    # Pre-register in known_bans so poll_bans doesn't double-alert
                    _cfg = load_config()
                    _known = set(_cfg.get("known_bans", []))
                    _known.add(f"{TABLE_POSTING}:{username}")
                    _cfg["known_bans"] = list(_known)
                    save_config(_cfg)
                await asyncio.sleep(SCHED_REQ_DELAY)
                continue

            # Build update dict — only update fields that have changed
            update_fields = {}
            if profile["post_karma"] != safe_get(r, "Post Karma", ""):
                update_fields["Post Karma"] = profile["post_karma"]
            if profile["comment_karma"] != safe_get(r, "Comment Karma", ""):
                update_fields["Comment Karma"] = profile["comment_karma"]
            if profile["account_age"] and profile["account_age"] != safe_get(r, "Account Age", ""):
                update_fields["Account Age"] = profile["account_age"]
            if profile["date_of_creation"] and profile["date_of_creation"] != safe_get(r, "Date of Creation", ""):
                update_fields["Date of Creation"] = profile["date_of_creation"]

            if update_fields:
                try:
                    get_table(TABLE_POSTING).update(r["id"], update_fields)
                    updated += 1
                except Exception as e:
                    logger.error(f"Airtable update error for u/{username}: {e}")
                    errors += 1

            await asyncio.sleep(SCHED_REQ_DELAY)

        # ── Also check WARMUP & BLANKS accounts for bans (batched) ────────────

        extra_tables = [
            (TABLE_WARMUP, "Warmup", ["Warming", "Ready"]),
            (TABLE_BLANKS, "Blanks", ["Available", "Taken"]),
        ]
        warmup_banned = []
        blanks_banned = []
        stage_lists = {"Warmup": warmup_banned, "Blanks": blanks_banned}

        for table_id, stage, active_statuses in extra_tables:
            try:
                records = get_table(table_id).all()
                stage_active = [r for r in records if safe_get(r, "Status") in active_statuses]
                to_check = [(r, safe_get(r, "Reddit Username", "").strip()) for r in stage_active]
                to_check = [(r, u) for r, u in to_check if u]
                logger.info(f"Checking {len(to_check)} {stage} accounts for bans...")

                for i, (r, username) in enumerate(to_check):
                    # Batch pause
                    if i > 0 and i % SCHED_BATCH == 0:
                        logger.info(f"{stage} ban check: {i}/{len(to_check)} done, pausing {SCHED_BATCH_PAUSE}s...")
                        await asyncio.sleep(SCHED_BATCH_PAUSE)

                    profile = await fetch_reddit_profile(username)
                    if not profile:
                        errors += 1
                        await asyncio.sleep(SCHED_REQ_DELAY)
                        continue

                    if profile.get("rate_limited"):
                        logger.warning(f"Reddit rate limited during {stage} check, pausing {SCHED_RATE_LIMIT_PAUSE}s...")
                        await asyncio.sleep(SCHED_RATE_LIMIT_PAUSE)
                        profile = await fetch_reddit_profile(username)
                        if not profile or profile.get("rate_limited"):
                            errors += 1
                            continue

                    if profile.get("suspended"):
                        va = safe_get(r, "VA", safe_get(r, "Created By", "N/A"))
                        model = safe_get(r, "Model", "N/A")
                        try:
                            get_table(table_id).update(r["id"], {"Status": "Banned"})
                        except Exception:
                            pass
                        proxy = safe_get(r, "Proxy Used", "").strip()
                        proxy_tag = f"🔒 {proxy}" if proxy else "⚠️ Proxy not mentioned"
                        stage_lists[stage].append(f"u/{username} ({va} / {model})\n      📍 {stage} | {proxy_tag}")
                        _cfg = load_config()
                        _known = set(_cfg.get("known_bans", []))
                        _known.add(f"{table_id}:{username}")
                        _cfg["known_bans"] = list(_known)
                        save_config(_cfg)

                    await asyncio.sleep(SCHED_REQ_DELAY)
            except Exception as e:
                logger.error(f"{stage} ban check error: {e}\n{traceback.format_exc()}")

        # Combine all banned lists
        all_suspended = suspended_list + warmup_banned + blanks_banned

        # Mark first refresh as done
        if is_first_refresh:
            cfg = load_config()
            cfg["refresh_seeded"] = True
            save_config(cfg)

        logger.info(
            f"Account update done: {updated} updated, {len(all_suspended)} newly banned "
            f"(posting:{len(suspended_list)} warmup:{len(warmup_banned)} blanks:{len(blanks_banned)}), "
            f"{errors} errors"
        )

        # Alert ban channel about newly discovered suspensions (skip first run)
        if all_suspended and not is_first_refresh:
            cfg = load_config()
            ban_channel = cfg.get("ban_channel")
            if ban_channel:
                text = (
                    f"<b>🔄 Auto-Refresh Found {len(all_suspended)} Banned Accounts</b>\n"
                    f"━━━━━━━━━━━━━━━━━━\n\n"
                )
                for s in all_suspended:
                    text += f"🚫 {s}\n"
                text += f"\n<i>Status auto-updated to Banned on Airtable</i>"
                kwargs = {"chat_id": int(ban_channel["chat_id"]), "text": text, "parse_mode": ParseMode.HTML}
                if ban_channel.get("thread_id"):
                    kwargs["message_thread_id"] = ban_channel["thread_id"]
                try:
                    await context.bot.send_message(**kwargs)
                except Exception as e:
                    logger.error(f"Failed to send refresh ban alert: {e}")
    except Exception as e:
        logger.error(f"Account info update error: {e}\n{traceback.format_exc()}")


async def refresh_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Manual trigger: /refresh — update all account karma/age from Reddit."""
    if not await is_admin(update, context):
        return await reply(update, "Admin only.")

    await reply(update, "🔄 Starting account refresh... this may take a few minutes.")

    try:
        posting = get_table(TABLE_POSTING).all()
        targets = [r for r in posting if safe_get(r, "Status") in ("Posting", "Dormant")]

        updated = 0
        newly_banned = 0
        errors = 0

        for r in targets:
            username = safe_get(r, "Reddit Username", "").strip()
            if not username:
                continue

            profile = await fetch_reddit_profile(username)
            if not profile:
                errors += 1
                await asyncio.sleep(3)
                continue

            if profile.get("rate_limited"):
                await reply(update, "⚠️ Reddit rate limited, waiting 120s...")
                await asyncio.sleep(120)
                profile = await fetch_reddit_profile(username)
                if not profile or profile.get("rate_limited"):
                    errors += 1
                    continue

            if profile.get("suspended"):
                newly_banned += 1
                current_status = safe_get(r, "Status")
                if current_status == "Posting":
                    try:
                        get_table(TABLE_POSTING).update(r["id"], {"Status": "Banned"})
                    except Exception:
                        pass
                await asyncio.sleep(2)
                continue

            update_fields = {}
            if profile["post_karma"] is not None:
                update_fields["Post Karma"] = profile["post_karma"]
            if profile["comment_karma"] is not None:
                update_fields["Comment Karma"] = profile["comment_karma"]
            if profile["account_age"]:
                update_fields["Account Age"] = profile["account_age"]
            if profile["date_of_creation"]:
                update_fields["Date of Creation"] = profile["date_of_creation"]

            if update_fields:
                try:
                    get_table(TABLE_POSTING).update(r["id"], update_fields)
                    updated += 1
                except Exception as e:
                    logger.error(f"Airtable update error for u/{username}: {e}")
                    errors += 1

            await asyncio.sleep(2)

        text = (
            f"<b>✅ Account Refresh Complete</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n\n"
            f"📊 Scanned: <b>{len(targets)}</b> accounts\n"
            f"🔄 Updated: <b>{updated}</b>\n"
        )
        if newly_banned:
            text += f"🚫 Newly suspended: <b>{newly_banned}</b>\n"
        if errors:
            text += f"⚠️ Errors: {errors}\n"
        text += f"\n<i>Karma, age & DOC synced from Reddit</i>"

        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"refresh error: {e}\n{traceback.format_exc()}")
        await reply(update, f"Error during refresh: {e}")


# ── /checkbans ── On-demand ban scan across all stages ────────────────────────


async def checkbans_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Manual trigger: /checkbans — scan all warmup, blanks & posting accounts for Reddit bans."""
    if not await is_admin(update, context):
        return await reply(update, "Admin only.")

    BATCH_SIZE = 5
    BATCH_PAUSE = 30   # seconds between batches
    REQUEST_DELAY = 5   # seconds between individual requests
    RATE_LIMIT_PAUSE = 120  # seconds when Reddit rate limits

    await reply(update, "🔍 Scanning ALL accounts across Blanks, Warmup & Posting for bans...\nProcessing in batches of 10 to avoid rate limits.")

    try:
        tables_to_scan = [
            (TABLE_BLANKS, "Blanks", ["Available", "Taken"]),
            (TABLE_WARMUP, "Warmup", ["Warming", "Ready"]),
            (TABLE_POSTING, "Posting", ["Posting", "Dormant"]),
        ]

        total_checked = 0
        total_banned = 0
        errors = 0
        ban_details = []

        for table_id, stage, active_statuses in tables_to_scan:
            records = get_table(table_id).all()
            active = [r for r in records if safe_get(r, "Status") in active_statuses]

            # Filter to only those with usernames
            to_check = [(r, safe_get(r, "Reddit Username", "").strip()) for r in active]
            to_check = [(r, u) for r, u in to_check if u]

            if not to_check:
                continue

            await reply(update, f"📋 <b>{stage}</b>: checking {len(to_check)} accounts...", parse_mode=ParseMode.HTML)

            stage_banned = 0
            for i, (r, username) in enumerate(to_check):
                # Batch pause: every BATCH_SIZE accounts, take a longer break
                if i > 0 and i % BATCH_SIZE == 0:
                    await reply(
                        update,
                        f"⏳ {stage}: checked {i}/{len(to_check)} — pausing {BATCH_PAUSE}s before next batch...",
                    )
                    await asyncio.sleep(BATCH_PAUSE)

                total_checked += 1
                profile = await fetch_reddit_profile(username)
                if not profile:
                    errors += 1
                    await asyncio.sleep(REQUEST_DELAY)
                    continue

                if profile.get("rate_limited"):
                    await reply(update, f"⚠️ Reddit rate limited during {stage} scan, waiting {RATE_LIMIT_PAUSE}s...")
                    await asyncio.sleep(RATE_LIMIT_PAUSE)
                    profile = await fetch_reddit_profile(username)
                    if not profile or profile.get("rate_limited"):
                        errors += 1
                        continue

                if profile.get("suspended"):
                    stage_banned += 1
                    total_banned += 1
                    va = safe_get(r, "VA", safe_get(r, "Created By", "N/A"))
                    model = safe_get(r, "Model", "N/A")
                    proxy = safe_get(r, "Proxy Used", "").strip()

                    # Update Airtable status to Banned
                    try:
                        get_table(table_id).update(r["id"], {"Status": "Banned"})
                    except Exception:
                        pass

                    # Pre-register in known_bans
                    _cfg = load_config()
                    _known = set(_cfg.get("known_bans", []))
                    _known.add(f"{table_id}:{username}")
                    _cfg["known_bans"] = list(_known)
                    save_config(_cfg)

                    proxy_tag = f"🔒 {proxy}" if proxy else "⚠️ No proxy"
                    ban_details.append(f"🚫 <b>u/{esc(username)}</b> — {stage} ({va} / {model})\n      {proxy_tag}")

                await asyncio.sleep(REQUEST_DELAY)

            # Stage summary
            await reply(
                update,
                f"✅ <b>{stage}</b> done: {len(to_check)} checked, {stage_banned} banned",
                parse_mode=ParseMode.HTML,
            )

        # Build final response
        text = (
            f"<b>✅ Ban Scan Complete</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n\n"
            f"📊 Checked: <b>{total_checked}</b> accounts\n"
            f"🚫 Newly banned: <b>{total_banned}</b>\n"
        )
        if errors:
            text += f"⚠️ Errors: {errors}\n"

        if ban_details:
            text += f"\n{'━' * 18}\n\n"
            for d in ban_details[:30]:
                text += f"{d}\n\n"
            if len(ban_details) > 30:
                text += f"<i>...and {len(ban_details) - 30} more</i>\n"
            text += f"\n<i>All statuses auto-updated to Banned in Airtable</i>"
        else:
            text += f"\n✨ <i>No new bans found — all accounts are alive!</i>"

        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"checkbans error: {e}\n{traceback.format_exc()}")
        await reply(update, f"Error during ban scan: {e}")


# ── /postcheck ── Quick shadowban / account status check ─────────────────────


async def postcheck_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Check if a Reddit account is shadowbanned/suspended right now."""
    if not context.args:
        return await reply(update, "Usage: <code>/postcheck username</code>", parse_mode=ParseMode.HTML)

    username = context.args[0].strip().lstrip("u/").lstrip("/")
    msg = await update.message.reply_text(f"Checking <b>u/{username}</b>...", parse_mode=ParseMode.HTML)

    profile = await fetch_reddit_profile(username)
    if not profile:
        return await msg.edit_text("Could not reach Reddit. Try again later.")

    if profile.get("rate_limited"):
        return await msg.edit_text("Reddit rate limited. Try again in a minute.")

    if profile.get("suspended"):
        text = (
            f"<b>🚫 u/{username} — SUSPENDED / BANNED</b>\n\n"
            f"Reddit returns 403/404 for this account.\n"
            f"🔗 https://old.reddit.com/user/{username}"
        )
    else:
        pk = int(profile.get("post_karma", 0))
        ck = int(profile.get("comment_karma", 0))
        text = (
            f"<b>✅ u/{username} — ALIVE</b>\n\n"
            f"Karma: <b>{pk + ck:,}</b> (Post: {pk:,} | Comment: {ck:,})\n"
            f"Age: {profile.get('account_age', 'N/A')}\n"
            f"Created: {profile.get('date_of_creation', 'N/A')}\n"
            f"🔗 https://old.reddit.com/user/{username}"
        )
    await msg.edit_text(text, parse_mode=ParseMode.HTML)


# ── /assign ── Reassign a posting account to a different VA ──────────────────


async def assign_acc_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Reassign a posting account: /assign <username> <va_name>"""
    if not await is_admin(update, context):
        return await reply(update, "Admin only.")
    if len(context.args) < 2:
        return await reply(
            update,
            "Usage: <code>/reassign username va_name</code>\nExample: <code>/reassign nightshiftmilk Lakshit</code>",
            parse_mode=ParseMode.HTML,
        )

    username = context.args[0].strip().lstrip("u/").lstrip("/").lower()
    new_va = " ".join(context.args[1:]).strip()

    try:
        posting = get_table(TABLE_POSTING).all()
        target = None
        for r in posting:
            if safe_get(r, "Reddit Username", "").strip().lower() == username:
                target = r
                break

        if not target:
            return await reply(update, f"Account <b>u/{username}</b> not found in Posting table.", parse_mode=ParseMode.HTML)

        # Find VA record for linking
        vas = get_table(TABLE_VAS).all()
        va_record = None
        # Match case-insensitive
        for v in vas:
            if safe_get(v, "VA Name", "").strip().lower() == new_va.lower():
                va_record = v
                new_va = safe_get(v, "VA Name")  # Use proper casing
                break

        update_fields = {"VA": new_va}
        if va_record:
            update_fields["Assigned VA"] = [va_record["id"]]

        get_table(TABLE_POSTING).update(target["id"], update_fields)

        old_va = safe_get(target, "VA", "None")
        await reply(
            update,
            f"<b>✅ Reassigned u/{username}</b>\n{old_va} → <b>{new_va}</b>",
            parse_mode=ParseMode.HTML,
        )
    except Exception as e:
        logger.error(f"assign error: {e}\n{traceback.format_exc()}")
        await reply(update, f"Error: {e}")


# ── /topaccs ── Highest karma accounts ───────────────────────────────────────


async def topaccs_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show top posting accounts by karma."""
    count = 15
    if context.args:
        try:
            count = min(int(context.args[0]), 30)
        except ValueError:
            pass

    try:
        posting = get_table(TABLE_POSTING).all()
        active = [r for r in posting if safe_get(r, "Status") in ("Posting", "Dormant")]

        # Calculate total karma for each
        scored = []
        for r in active:
            try:
                pk = int(safe_get(r, "Post Karma", "0") or 0)
            except (ValueError, TypeError):
                pk = 0
            try:
                ck = int(safe_get(r, "Comment Karma", "0") or 0)
            except (ValueError, TypeError):
                ck = 0
            total = pk + ck
            scored.append((total, pk, ck, r))

        scored.sort(key=lambda x: x[0], reverse=True)
        top = scored[:count]

        if not top:
            return await reply(update, "No active accounts with karma data.")

        text = f"<b>🏆 Top {len(top)} Accounts by Karma</b>\n━━━━━━━━━━━━━━━━━━\n\n"
        for i, (total, pk, ck, r) in enumerate(top, 1):
            uname = safe_get(r, "Reddit Username", "?")
            va = safe_get(r, "VA", "?")
            model = safe_get(r, "Model", "?")
            age = safe_get(r, "Account Age", "?")
            medal = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else f"  {i}."
            text += f"{medal} <b>u/{uname}</b> — {total:,} karma\n"
            text += f"     {va} | {model} | Age: {age}\n\n"

        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"topaccs error: {e}\n{traceback.format_exc()}")
        await reply(update, f"Error: {e}")


# ── /warnings ── Accounts with low activity or potential issues ──────────────


async def warnings_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show accounts that might need attention: zero karma, no recent posts, etc."""
    try:
        posting = get_table(TABLE_POSTING).all()
        logs = get_table(TABLE_POSTING_LOGS).all()
        active = [r for r in posting if safe_get(r, "Status") == "Posting"]

        # Build set of usernames with posts in last 7 days
        week_ago = now_utc() - timedelta(days=7)
        recent_posters = set()
        _ensure_va_cache()
        for r in logs:
            d = parse_date_loose(safe_get(r, "Post Date"))
            if d and d > week_ago:
                va_name = _get_log_va_name(r)
                recent_posters.add(va_name)

        # Build account-level post counts from logs (by Reddit Account link)
        acc_post_urls = defaultdict(int)
        for r in logs:
            d = parse_date_loose(safe_get(r, "Post Date"))
            if d and d > week_ago:
                url = safe_get(r, "Post URL", "")
                acc_post_urls[url] += 1

        zero_karma = []
        no_posts = []

        for r in active:
            uname = safe_get(r, "Reddit Username", "").strip()
            if not uname:
                continue
            va = safe_get(r, "VA", "?")
            model = safe_get(r, "Model", "?")
            proxy = safe_get(r, "Proxy Used", "")

            # Check zero karma
            try:
                pk = int(safe_get(r, "Post Karma", "0") or 0)
            except (ValueError, TypeError):
                pk = 0
            try:
                ck = int(safe_get(r, "Comment Karma", "0") or 0)
            except (ValueError, TypeError):
                ck = 0

            if pk + ck == 0:
                zero_karma.append(f"  u/{uname} — {va} | {model}")

        text = f"<b>⚠️ Account Warnings</b>\n━━━━━━━━━━━━━━━━━━\n\n"
        has_warnings = False

        if zero_karma:
            has_warnings = True
            text += f"<b>0 Karma ({len(zero_karma)} accounts)</b>\n"
            for line in zero_karma[:15]:
                text += f"{line}\n"
            if len(zero_karma) > 15:
                text += f"  <i>...and {len(zero_karma) - 15} more</i>\n"
            text += "\n"

        # VAs with no posts this week
        va_names = set()
        for r in active:
            va_names.add(safe_get(r, "VA", ""))
        inactive_vas = [v for v in va_names if v and v not in recent_posters]
        if inactive_vas:
            has_warnings = True
            text += f"<b>No Posts This Week</b>\n"
            for v in sorted(inactive_vas):
                text += f"  {v}\n"
            text += "\n"

        # Accounts with low karma (1-10) that might be at risk
        low_karma = []
        for r in active:
            uname = safe_get(r, "Reddit Username", "").strip()
            if not uname:
                continue
            try:
                pk = int(safe_get(r, "Post Karma", "0") or 0)
                ck = int(safe_get(r, "Comment Karma", "0") or 0)
            except (ValueError, TypeError):
                continue
            total = pk + ck
            if 1 <= total <= 10:
                va = safe_get(r, "VA", "?")
                low_karma.append(f"  u/{uname} — {total} karma | {va}")

        if low_karma:
            has_warnings = True
            text += f"<b>Low Karma (1-10) — Ban Risk ({len(low_karma)})</b>\n"
            for line in low_karma[:10]:
                text += f"{line}\n"
            if len(low_karma) > 10:
                text += f"  <i>...and {len(low_karma) - 10} more</i>\n"
            text += "\n"

        if not has_warnings:
            text += "All clear — no warnings right now."

        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"warnings error: {e}\n{traceback.format_exc()}")
        await reply(update, f"Error: {e}")


# ── /status ── Operations dashboard (24h default, /status 7d for weekly) ─────


async def status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Parse time range: default 24h, "7d" for weekly
    arg = (context.args[0].lower() if context.args else "").strip()
    is_weekly = arg in ("7d", "7days", "week", "weekly")
    range_hours = 168 if is_weekly else 24
    range_label = "7 Days" if is_weekly else "24 Hours"

    await reply(update, f"Fetching {range_label.lower()} stats...")
    try:
        blanks = get_table(TABLE_BLANKS).all()
        warmup = get_table(TABLE_WARMUP).all()
        posting = get_table(TABLE_POSTING).all()
        logs = get_table(TABLE_POSTING_LOGS).all()

        cutoff = now_utc() - timedelta(hours=range_hours)

        # ── POSTING LOGS in range ──
        va_posts = Counter()
        va_last_post = {}
        hourly = Counter()
        total_posts = 0

        for r in logs:
            d = parse_date_loose(safe_get(r, "Post Date"))
            if not d or d < cutoff:
                continue
            total_posts += 1
            name = _get_log_va_name(r)
            va_posts[name] += 1
            d_ist = to_ist(d)
            hourly[d_ist.hour] += 1
            if name not in va_last_post or d > va_last_post[name]:
                va_last_post[name] = d

        # ── POSTING ACCOUNTS ──
        va_active = Counter()
        va_models = defaultdict(lambda: Counter())
        p_banned = p_shadow = 0
        for r in posting:
            status = safe_get(r, "Status")
            va = safe_get(r, "VA", "Unassigned")
            model = safe_get(r, "Model", "?")
            if status == "Posting":
                va_active[va] += 1
                va_models[va][model] += 1
            elif status == "Banned":
                p_banned += 1
            elif status == "Shadowbanned":
                p_shadow += 1

        # ── WARMUP (active only, recent bans) ──
        va_warming = Counter()
        va_warmed = Counter()
        w_recent_bans = 0
        for r in warmup:
            status = safe_get(r, "Status")
            va = safe_get(r, "VA", "Unassigned")
            if status == "Warming Up":
                va_warming[va] += 1
            elif status == "Warmed Up":
                va_warmed[va] += 1
            elif status in ("Banned", "Taken&Banned"):
                created = parse_date_loose(r.get("createdTime", ""))
                if created and created >= cutoff:
                    w_recent_bans += 1

        # ── BLANKS in range ──
        blanks_range = Counter()
        b_available = 0
        for r in blanks:
            if safe_get(r, "Status") == "Available":
                b_available += 1
            d = parse_date_loose(safe_get(r, "Date Created", ""))
            if d and d >= cutoff:
                blanks_range[safe_get(r, "Created By", "Unknown")] += 1

        # ── BUILD MESSAGE ──
        t = now_ist().strftime("%I:%M %p IST")
        text = (
            f"<b>📊 Operations — Last {range_label}</b>\n"
            f"<i>{t} | /status {'7d' if not is_weekly else ''} for {'weekly' if not is_weekly else '24h'}</i>\n"
            "━━━━━━━━━━━━━━━━━━\n\n"
        )

        # --- POSTS ---
        text += f"<b>📮 {total_posts} Posts</b>\n"
        if va_posts:
            for va, count in va_posts.most_common():
                last = ist_fmt(va_last_post.get(va))
                avg = f" ({count / 7:.1f}/day)" if is_weekly else ""
                text += f"  {va}: <b>{count}</b>{avg} — last: {last}\n"
        else:
            text += "  No posts in this period\n"

        # Posting times
        if hourly and not is_weekly:
            text += "\n  <b>⏰ Activity by hour:</b>\n  "
            parts = []
            for h in sorted(hourly.keys()):
                ampm = "AM" if h < 12 else "PM"
                h12 = h % 12 or 12
                parts.append(f"{h12}{ampm}:<b>{hourly[h]}</b>")
            text += " | ".join(parts) + "\n"

        # --- ACTIVE ACCOUNTS ---
        total_active = sum(va_active.values())
        text += f"\n<b>🟢 {total_active} Active Accounts</b>\n"
        for va, count in va_active.most_common():
            if va == "Unassigned":
                continue
            m_str = ", ".join(f"{m}:{c}" for m, c in va_models[va].most_common())
            text += f"  {va}: <b>{count}</b> ({m_str})\n"
        text += f"  🚫 Banned: {p_banned} | 👻 Shadow: {p_shadow}\n"

        # --- WARMUP ---
        total_warming = sum(va_warming.values())
        total_warmed = sum(va_warmed.values())
        text += f"\n<b>♨️ Warmup — {total_warming} warming | {total_warmed} ready</b>\n"
        for va in sorted(set(list(va_warming) + list(va_warmed))):
            if va == "Unassigned":
                continue
            p = []
            if va_warming[va]:
                p.append(f"🔥{va_warming[va]}")
            if va_warmed[va]:
                p.append(f"✅{va_warmed[va]}")
            if p:
                text += f"  {va}: {' | '.join(p)}\n"
        if w_recent_bans:
            text += f"  🚫 Recent bans: {w_recent_bans}\n"

        # --- BLANKS ---
        total_new_blanks = sum(blanks_range.values())
        text += f"\n<b>🆕 Blanks — {b_available} available | {total_new_blanks} new</b>\n"
        if blanks_range:
            for creator, count in blanks_range.most_common():
                text += f"  {creator}: <b>{count}</b> created\n"
        else:
            text += f"  No new blanks in last {range_label.lower()}\n"

        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"status error: {e}\n{traceback.format_exc()}")
        await reply(update, f"Error fetching status: {e}")


# ── /blanks ── Detailed blanks report ─────────────────────────────────────────

async def blanks_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    arg = (context.args[0].lower() if context.args else "").strip()
    is_weekly = arg in ("7d", "7days", "week", "weekly")
    range_hours = 168 if is_weekly else 24
    range_label = "7 Days" if is_weekly else "24 Hours"
    cutoff = now_utc() - timedelta(hours=range_hours)

    await reply(update, f"Fetching blanks ({range_label.lower()})...")
    try:
        blanks = get_table(TABLE_BLANKS).all()
        last_24h = now_utc() - timedelta(hours=24)
        last_7d = now_utc() - timedelta(days=7)

        b_status = count_by_field(blanks, "Status")
        available = b_status.get("Available", 0)
        taken = b_status.get("Taken", 0)
        banned = b_status.get("Banned", 0)

        # Per-VA creation in 24h and 7d
        va_24h = Counter()
        va_7d = Counter()
        va_all = Counter()
        va_proxy = defaultdict(Counter)
        recent_blanks = []  # last 24h blanks with details

        for r in blanks:
            creator = safe_get(r, "Created By", "Unknown")
            va_all[creator] += 1

            date_str = safe_get(r, "Date Created", "")
            d = parse_date_loose(date_str)
            proxy = safe_get(r, "Proxy Used", "").strip()
            if proxy:
                va_proxy[creator][proxy[:30]] += 1

            if d:
                if d >= last_24h:
                    va_24h[creator] += 1
                    username = safe_get(r, "Reddit Username", "?")
                    status = safe_get(r, "Status", "?")
                    recent_blanks.append({
                        "user": username,
                        "creator": creator,
                        "time": ist_fmt(d),
                        "status": status,
                        "proxy": proxy[:20] if proxy else "N/A",
                    })
                if d >= last_7d:
                    va_7d[creator] += 1

        text = (
            "<b>🆕 Blanks Creation Report</b>\n"
            "━━━━━━━━━━━━━━━━━━\n\n"
            f"✅ Available: <b>{available}</b> | 📌 Taken: {taken} | 🚫 Banned: {banned}\n\n"
        )

        # Per-VA: Last 24h
        text += "<b>📅 Created in Last 24 Hours:</b>\n"
        if va_24h:
            for creator, count in va_24h.most_common():
                text += f"  {creator}: <b>{count}</b> blanks\n"
            text += f"  <i>Total: {sum(va_24h.values())}</i>\n"
        else:
            text += "  No new blanks in 24h\n"

        # Per-VA: Last 7 days
        text += "\n<b>📅 Created in Last 7 Days:</b>\n"
        if va_7d:
            for creator, count in va_7d.most_common():
                text += f"  {creator}: <b>{count}</b> blanks\n"
            text += f"  <i>Total: {sum(va_7d.values())}</i>\n"
        else:
            text += "  No blanks in last 7 days\n"

        # All time per VA
        text += "\n<b>📊 All Time by Creator:</b>\n"
        for creator, count in va_all.most_common():
            if creator and creator != "Unknown":
                text += f"  {creator}: {count}\n"

        # Recent blanks detail (last 24h)
        if recent_blanks:
            text += "\n<b>🕐 Recent Blanks (24h):</b>\n"
            for b in recent_blanks[:15]:  # cap at 15
                emoji = "✅" if b["status"] == "Available" else "🚫" if b["status"] == "Banned" else "📌"
                text += f"  {emoji} u/{b['user']} — {b['creator']} @ {b['time']}\n"
            if len(recent_blanks) > 15:
                text += f"  <i>...and {len(recent_blanks) - 15} more</i>\n"

        # Proxy usage
        text += "\n<b>🔒 Proxy Usage by Creator:</b>\n"
        for creator, proxies in sorted(va_proxy.items()):
            if creator and creator != "Unknown":
                top_proxies = proxies.most_common(3)
                proxy_str = ", ".join(f"{p} ({c})" for p, c in top_proxies)
                text += f"  {creator}: {proxy_str}\n"

        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"blanks error: {e}\n{traceback.format_exc()}")
        await reply(update, f"Error fetching blanks: {e}")


# ── /warmup ── Detailed warmup report ─────────────────────────────────────────

async def warmup_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    arg = (context.args[0].lower() if context.args else "").strip()
    is_weekly = arg in ("7d", "7days", "week", "weekly")
    range_hours = 168 if is_weekly else 24
    range_label = "7 Days" if is_weekly else "24 Hours"
    cutoff = now_utc() - timedelta(hours=range_hours)

    await reply(update, f"Fetching warmup ({range_label.lower()})...")
    try:
        warmup = get_table(TABLE_WARMUP).all()

        # Per-VA: only active warming accounts + recently created records
        va_warming = defaultdict(lambda: {"count": 0, "days": Counter(), "proxies": Counter()})
        va_warmed = Counter()
        recent_added = Counter()  # records created in time range
        recent_bans = 0

        for r in warmup:
            status = safe_get(r, "Status", "Unknown")
            va = safe_get(r, "VA", "Unassigned")
            day = safe_get(r, "Warmup Day", "-")
            proxy = safe_get(r, "Proxy Used", "").strip()

            # Record creation time from Airtable metadata
            created = parse_date_loose(r.get("createdTime", ""))

            if status == "Warming Up":
                va_warming[va]["count"] += 1
                va_warming[va]["days"][day] += 1
                if proxy:
                    va_warming[va]["proxies"][proxy[:25]] += 1
            elif status == "Warmed Up":
                va_warmed[va] += 1

            # Track recent activity using record creation time
            if created and created >= cutoff:
                recent_added[va] += 1
            # Recent bans (records that are currently banned AND were created recently)
            if status in ("Banned", "Taken&Banned") and created and created >= cutoff:
                recent_bans += 1

        total_warming = sum(d["count"] for d in va_warming.values())
        total_warmed = sum(va_warmed.values())

        text = (
            f"<b>Warmup — Last {range_label}</b>\n"
            f"<i>/warmup {'7d' if not is_weekly else ''} for {'weekly' if not is_weekly else '24h'}</i>\n"
            "————————————————\n\n"
            f"Warming: <b>{total_warming}</b> | Ready: <b>{total_warmed}</b>"
        )
        if recent_bans:
            text += f" | Banned: <b>{recent_bans}</b>"
        text += "\n"
        if recent_added:
            text += f"New (last {range_label.lower()}): <b>{sum(recent_added.values())}</b>\n"
        text += "\n<b>— Warming by VA —</b>\n"

        for va in sorted(va_warming.keys()):
            if va == "Unassigned":
                continue
            d = va_warming[va]
            if d["count"] == 0:
                continue

            text += f"\n<b>{va}</b> — {d['count']} accounts\n"
            # Day distribution
            day_parts = []
            for day_num in range(11):
                day_key = f"Day {day_num}"
                if d["days"][day_key]:
                    day_parts.append(f"D{day_num}: {d['days'][day_key]}")
            if day_parts:
                text += f"  Days: {' | '.join(day_parts)}\n"
            # Proxies — name + account count
            if d["proxies"]:
                parts = [f"{p} on {c} accounts" for p, c in d["proxies"].most_common(5)]
                label = "Proxy" if len(parts) == 1 else "Proxies"
                text += f"  {label}: {', '.join(parts)}\n"
            # Recently added for this VA
            if recent_added[va]:
                text += f"  New: {recent_added[va]}\n"

        # Warmed up ready
        if total_warmed:
            text += "\n<b>— Ready for Posting —</b>\n"
            for va, c in va_warmed.most_common():
                if va != "Unassigned" and c > 0:
                    text += f"  {va}: {c}\n"

        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"warmup error: {e}\n{traceback.format_exc()}")
        await reply(update, f"Error fetching warmup: {e}")


# ── /posting ── Detailed posting report ───────────────────────────────────────

async def posting_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    arg = (context.args[0].lower() if context.args else "").strip()
    is_weekly = arg in ("7d", "7days", "week", "weekly")
    range_hours = 168 if is_weekly else 24
    range_label = "7 Days" if is_weekly else "24 Hours"
    cutoff = now_utc() - timedelta(hours=range_hours)

    await reply(update, f"Fetching posting ({range_label.lower()})...")
    try:
        posting = get_table(TABLE_POSTING).all()
        logs = get_table(TABLE_POSTING_LOGS).all()

        # ── Per-VA account + karma breakdown ──
        va_data = defaultdict(lambda: {
            "active": 0, "dormant": 0, "banned": 0, "shadow": 0,
            "models": Counter(), "karma": 0, "locations": Counter(),
            "accounts": [],
        })

        for r in posting:
            va = safe_get(r, "VA", "Unassigned")
            status = safe_get(r, "Status", "Unknown")
            model = safe_get(r, "Model", "Unknown")
            location = safe_get(r, "Location", "")
            username = safe_get(r, "Reddit Username", "?")

            if status == "Posting":
                va_data[va]["active"] += 1
                va_data[va]["accounts"].append(username)
            elif status == "Dormant":
                va_data[va]["dormant"] += 1
            elif status == "Banned":
                va_data[va]["banned"] += 1
            elif status == "Shadowbanned":
                va_data[va]["shadow"] += 1

            va_data[va]["models"][model] += 1
            if location:
                va_data[va]["locations"][location] += 1
            try:
                va_data[va]["karma"] += int(safe_get(r, "Post Karma", "0")) + int(safe_get(r, "Comment Karma", "0"))
            except (ValueError, TypeError):
                pass

        # ── Per-VA posting activity from logs ──
        va_today = Counter()
        va_week = Counter()
        va_last_post = {}
        hourly_today = Counter()

        for r in logs:
            d = parse_date_loose(safe_get(r, "Post Date"))
            if not d or d < cutoff:
                continue
            name = _get_log_va_name(r)
            d_ist = to_ist(d)
            va_today[name] += 1
            hourly_today[d_ist.hour] += 1
            va_week[name] += 1
            if name not in va_last_post or d > va_last_post[name]:
                va_last_post[name] = d

        # ── BUILD MESSAGE ──
        total_active = sum(d["active"] for d in va_data.values())
        total_banned = sum(d["banned"] for d in va_data.values())
        total_shadow = sum(d["shadow"] for d in va_data.values())
        total_karma = sum(d["karma"] for d in va_data.values())

        text = (
            f"<b>📮 Posting Report — Last {range_label}</b>\n"
            f"<i>/posting {'7d' if not is_weekly else ''} for {'weekly' if not is_weekly else '24h'}</i>\n"
            "━━━━━━━━━━━━━━━━━━\n\n"
            f"🟢 Active: <b>{total_active}</b> | 🚫 Banned: {total_banned} | 👻 Shadow: {total_shadow}\n"
            f"💎 Total Karma: {total_karma:,}\n\n"
        )

        # Per-VA detail
        text += "<b>📋 Per VA:</b>\n"
        for va in sorted(va_data.keys()):
            if va == "Unassigned":
                continue
            d = va_data[va]
            if d["active"] == 0 and d["banned"] == 0:
                continue
            models_str = ", ".join(f"{m}:{c}" for m, c in d["models"].most_common() if m != "Unknown")
            posts_range = va_today.get(va, 0)
            last = ist_fmt(va_last_post.get(va))
            total_accs = d["active"] + d["banned"] + d["shadow"] + d["dormant"]
            ban_rate = (d["banned"] + d["shadow"]) / total_accs * 100 if total_accs else 0

            text += (
                f"\n<b>  {va}</b>\n"
                f"    🟢 {d['active']} active | 🚫 {d['banned']} ban | 👻 {d['shadow']} shadow ({ban_rate:.0f}%)\n"
                f"    📝 Posts ({range_label.lower()}): <b>{posts_range}</b>\n"
                f"    🕐 Last post: {last}\n"
                f"    🎭 {models_str}\n"
                f"    💎 Karma: {d['karma']:,}\n"
            )

        # Hourly posting distribution today
        if hourly_today:
            text += "\n<b>🕐 Today's Posting Times (IST):</b>\n  "
            hour_parts = []
            for h in sorted(hourly_today.keys()):
                ampm = "AM" if h < 12 else "PM"
                h12 = h % 12 or 12
                hour_parts.append(f"{h12}{ampm}:{hourly_today[h]}")
            text += " | ".join(hour_parts) + "\n"

        # Top locations
        all_locs = Counter()
        for d in va_data.values():
            all_locs.update(d["locations"])
        if all_locs:
            text += "\n<b>📍 Top Locations:</b>\n"
            for loc, c in all_locs.most_common(8):
                text += f"  {loc}: {c}\n"

        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"posting error: {e}\n{traceback.format_exc()}")
        await reply(update, f"Error fetching posting: {e}")


# ── /logs ── Posting logs summary ─────────────────────────────────────────────

async def logs_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    arg = (context.args[0].lower() if context.args else "").strip()
    is_weekly = arg in ("7d", "7days", "week", "weekly")
    range_hours = 168 if is_weekly else 24
    range_label = "7 Days" if is_weekly else "24 Hours"
    cutoff = now_utc() - timedelta(hours=range_hours)

    await reply(update, f"Fetching logs ({range_label.lower()})...")
    try:
        logs = get_table(TABLE_POSTING_LOGS).all()

        va_posts = Counter()
        va_last_time = {}
        hourly = Counter()
        recent_posts = []
        total = 0

        for r in logs:
            d = parse_date_loose(safe_get(r, "Post Date"))
            if not d or d < cutoff:
                continue
            total += 1
            name = _get_log_va_name(r)
            va_posts[name] += 1
            d_ist = to_ist(d)
            hourly[d_ist.hour] += 1
            if name not in va_last_time or d > va_last_time[name]:
                va_last_time[name] = d

            url = safe_get(r, "Post URL", "")
            recent_posts.append({
                "va": name,
                "url": url[:50] if url else "N/A",
                "time": d_ist.strftime("%I:%M %p"),
                "date": d_ist.strftime("%b %d"),
                "dt": d,
            })

        # Sort recent posts newest first
        recent_posts.sort(key=lambda x: x["dt"], reverse=True)

        text = (
            f"<b>📝 Posting Logs — Last {range_label}</b>\n"
            f"<i>/logs {'7d' if not is_weekly else ''} for {'weekly' if not is_weekly else '24h'}</i>\n"
            "━━━━━━━━━━━━━━━━━━\n\n"
            f"<b>Total Posts:</b> {total}\n\n"
        )

        # Per-VA breakdown
        text += "<b>📊 By VA:</b>\n"
        if va_posts:
            for va, count in va_posts.most_common():
                last = ist_fmt(va_last_time.get(va))
                avg = f" ({count / 7:.1f}/day)" if is_weekly else ""
                text += f"  {va}: <b>{count}</b>{avg} — last: {last}\n"
        else:
            text += "  No posts in this period\n"

        # Hourly distribution
        if hourly:
            text += "\n<b>⏰ By Hour (IST):</b>\n  "
            parts = []
            for h in sorted(hourly.keys()):
                ampm = "AM" if h < 12 else "PM"
                h12 = h % 12 or 12
                parts.append(f"{h12}{ampm}:<b>{hourly[h]}</b>")
            text += " | ".join(parts) + "\n"

        # Recent posts (last 15)
        if recent_posts:
            text += f"\n<b>🕐 Recent Posts:</b>\n"
            for p in recent_posts[:15]:
                text += f"  {p['va']} @ {p['time']} {p['date']}\n"
            if len(recent_posts) > 15:
                text += f"  <i>...{len(recent_posts) - 15} more</i>\n"

        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"logs error: {e}\n{traceback.format_exc()}")
        await reply(update, f"Error fetching logs: {e}")


# ── /bans ── Ban report ───────────────────────────────────────────────────────

async def bans_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    arg = (context.args[0].lower() if context.args else "").strip()
    is_weekly = arg in ("7d", "7days", "week", "weekly")
    show_all = arg in ("all", "total")
    range_hours = 168 if is_weekly else 24
    range_label = "7 Days" if is_weekly else "24 Hours"
    cutoff = now_utc() - timedelta(hours=range_hours)

    await reply(update, f"Fetching ban report ({range_label.lower() if not show_all else 'all time'})...")
    try:
        blanks = get_table(TABLE_BLANKS).all()
        warmup = get_table(TABLE_WARMUP).all()
        posting = get_table(TABLE_POSTING).all()

        # Recent bans: use Airtable record createdTime to find accounts
        # that were marked as banned within the time range
        recent_blanks_banned = []
        recent_warmup_banned = []
        recent_posting_banned = []
        recent_posting_shadow = []

        # Also keep all-time counts for summary line
        all_blanks_banned = 0
        all_warmup_banned = 0
        all_posting_banned = 0
        all_posting_shadow = 0

        for r in blanks:
            if safe_get(r, "Status") == "Banned":
                all_blanks_banned += 1
                created = parse_date_loose(r.get("createdTime", ""))
                if show_all or (created and created >= cutoff):
                    recent_blanks_banned.append(r)

        for r in warmup:
            if safe_get(r, "Status") in ("Banned", "Taken&Banned"):
                all_warmup_banned += 1
                created = parse_date_loose(r.get("createdTime", ""))
                if show_all or (created and created >= cutoff):
                    recent_warmup_banned.append(r)

        for r in posting:
            status = safe_get(r, "Status")
            if status == "Banned":
                all_posting_banned += 1
                created = parse_date_loose(r.get("createdTime", ""))
                if show_all or (created and created >= cutoff):
                    recent_posting_banned.append(r)
            elif status == "Shadowbanned":
                all_posting_shadow += 1
                created = parse_date_loose(r.get("createdTime", ""))
                if show_all or (created and created >= cutoff):
                    recent_posting_shadow.append(r)

        total_posting = len(posting)
        ban_rate = (all_posting_banned + all_posting_shadow) / total_posting * 100 if total_posting else 0

        # Per-VA recent ban count
        va_bans = Counter()
        for r in recent_posting_banned + recent_posting_shadow:
            va_bans[safe_get(r, "VA", "Unknown")] += 1

        # Per-model recent ban count
        model_bans = Counter()
        for r in recent_posting_banned + recent_posting_shadow:
            model_bans[safe_get(r, "Model", "Unknown")] += 1

        period = "All Time" if show_all else f"Last {range_label}"
        text = (
            f"<b>🚫 Ban Report — {period}</b>\n"
            f"<i>/bans {'7d' if not is_weekly and not show_all else 'all' if not show_all else ''} for "
            f"{'weekly' if not is_weekly and not show_all else 'all time' if not show_all else '24h'}</i>\n"
            "━━━━━━━━━━━━━━━━━━\n\n"
        )

        # Recent bans summary
        text += f"<b>Recent ({period}):</b>\n"
        text += f"  Blanks: {len(recent_blanks_banned)} banned\n"
        text += f"  Warmup: {len(recent_warmup_banned)} banned\n"
        text += f"  Posting: {len(recent_posting_banned)} banned + {len(recent_posting_shadow)} shadow\n\n"

        # All-time totals (compact)
        if not show_all:
            text += f"<i>All time: B:{all_blanks_banned} W:{all_warmup_banned} P:{all_posting_banned}+{all_posting_shadow}shadow ({ban_rate:.0f}%)</i>\n\n"

        # Recent bans by VA
        if va_bans:
            text += f"<b>By VA ({period}):</b>\n"
            for va, c in va_bans.most_common():
                text += f"  {va}: {c}\n"
            text += "\n"

        # Recent bans by model
        if model_bans:
            text += f"<b>By Model ({period}):</b>\n"
            for m, c in model_bans.most_common():
                text += f"  {m}: {c}\n"
            text += "\n"

        # List recent banned usernames with stage + proxy
        all_recent_with_stage = (
            [(r, "Blanks") for r in recent_blanks_banned]
            + [(r, "Warmup") for r in recent_warmup_banned]
            + [(r, "Posting") for r in recent_posting_banned]
            + [(r, "Posting") for r in recent_posting_shadow]
        )
        if all_recent_with_stage:
            text += f"<b>Banned Accounts ({period}):</b>\n"
            for r, stage in all_recent_with_stage[:25]:
                username = safe_get(r, "Reddit Username", "?")
                va = safe_get(r, "VA", "?")
                status = safe_get(r, "Status")
                emoji = "👻" if status == "Shadowbanned" else "🚫"
                proxy = safe_get(r, "Proxy Used", "").strip()
                proxy_str = f"🔒 {proxy}" if proxy else "⚠️ Proxy not mentioned"
                text += (
                    f"  {emoji} u/{username} — {va}\n"
                    f"      📍 {stage} | {proxy_str}\n"
                )
            if len(all_recent_with_stage) > 25:
                text += f"  <i>...{len(all_recent_with_stage) - 25} more</i>\n"

        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"bans error: {e}\n{traceback.format_exc()}")
        await reply(update, f"Error fetching bans: {e}")


# ── /accounts ── Per-model account breakdown ──────────────────────────────────

async def accounts_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await reply(update, "Fetching accounts breakdown...")
    try:
        posting = get_table(TABLE_POSTING).all()

        filter_model = " ".join(context.args).strip() if context.args else None

        models = defaultdict(lambda: Counter())
        for r in posting:
            model = safe_get(r, "Model", "Unknown")
            status = safe_get(r, "Status", "Unknown")
            models[model][status] += 1

        if filter_model:
            # Filter to specific model (case insensitive)
            matched = None
            for m in models:
                if m.lower() == filter_model.lower():
                    matched = m
                    break
            if not matched:
                return await reply(update, f"Model '{filter_model}' not found. Available: {', '.join(models.keys())}")
            models = {matched: models[matched]}

        text = "<b>🔍 Accounts by Model</b>\n━━━━━━━━━━━━━━━━━━\n\n"
        for model, statuses in sorted(models.items()):
            total = sum(statuses.values())
            text += f"<b>{model}</b> ({total} total)\n"
            for s, c in sorted(statuses.items(), key=lambda x: -x[1]):
                text += f"  {s}: {c}\n"
            text += "\n"

        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"accounts error: {e}\n{traceback.format_exc()}")
        await reply(update, f"Error fetching accounts: {e}")


# ── /mystats ── Personal VA stats ─────────────────────────────────────────────

async def mystats_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cfg = load_config()
    user_id = str(update.effective_user.id)
    va_name = cfg.get("va_map", {}).get(user_id)

    if not va_name:
        return await reply(
            update,
            "You're not linked to a VA. Ask an admin to run:\n"
            "<code>/linkva YourName</code> (reply to your message)",
            parse_mode=ParseMode.HTML,
        )

    await reply(update, f"Fetching stats for {va_name}...")
    try:
        posting = get_table(TABLE_POSTING).all()
        logs = get_table(TABLE_POSTING_LOGS).all()

        # My accounts
        my_accounts = [r for r in posting if safe_get(r, "VA") == va_name]
        active = sum(1 for r in my_accounts if safe_get(r, "Status") == "Posting")
        banned = sum(1 for r in my_accounts if safe_get(r, "Status") in ("Banned", "Shadowbanned"))
        ban_rate = banned / len(my_accounts) * 100 if my_accounts else 0

        # My logs (match via VAs linked field)
        today = start_of_today()
        week_start = start_of_week()
        today_posts = 0
        week_posts = 0

        _ensure_va_cache()
        for r in logs:
            log_va = _get_log_va_name(r)
            if log_va != va_name:
                continue
            d = parse_date_loose(safe_get(r, "Post Date"))
            if d and d >= today:
                today_posts += 1
            if d and d >= week_start:
                week_posts += 1

        # Total karma
        total_karma = 0
        for r in my_accounts:
            try:
                total_karma += int(safe_get(r, "Post Karma", "0")) + int(safe_get(r, "Comment Karma", "0"))
            except (ValueError, TypeError):
                pass

        text = (
            f"<b>📈 Your Stats — {va_name}</b>\n"
            "━━━━━━━━━━━━━━━━━━\n\n"
            f"<b>Posts Today:</b> {today_posts}\n"
            f"<b>Posts This Week:</b> {week_posts}\n\n"
            f"<b>Accounts:</b> {len(my_accounts)} total\n"
            f"  🟢 Active: {active}\n"
            f"  🚫 Banned: {banned}\n"
            f"  📊 Ban Rate: {ban_rate:.1f}%\n\n"
            f"<b>Total Karma:</b> {total_karma:,}\n"
        )
        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"mystats error: {e}\n{traceback.format_exc()}")
        await reply(update, f"Error: {e}")


# ── /vastats ── VA performance dashboard (admin) ──────────────────────────────

async def vastats_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await reply(update, "Admin only.")

    await reply(update, "Fetching VA performance...")
    try:
        vas = get_table(TABLE_VAS).all()
        posting = get_table(TABLE_POSTING).all()
        logs = get_table(TABLE_POSTING_LOGS).all()

        week_start = start_of_week()
        today = start_of_today()

        # Build VA stats
        va_stats = {}
        for v in vas:
            name = safe_get(v, "VA Name")
            if not name:
                continue
            expected = safe_get(v, "Expected Posts Per Day", 0)
            va_stats[name] = {
                "expected": expected or 0,
                "accounts": 0,
                "active": 0,
                "banned": 0,
                "today": 0,
                "week": 0,
                "karma": 0,
            }

        # Count accounts per VA
        for r in posting:
            va = safe_get(r, "VA")
            if va and va in va_stats:
                va_stats[va]["accounts"] += 1
                status = safe_get(r, "Status")
                if status == "Posting":
                    va_stats[va]["active"] += 1
                elif status in ("Banned", "Shadowbanned"):
                    va_stats[va]["banned"] += 1
                try:
                    va_stats[va]["karma"] += int(safe_get(r, "Post Karma", "0")) + int(safe_get(r, "Comment Karma", "0"))
                except (ValueError, TypeError):
                    pass

        # Count posts per VA (using VAs linked field)
        _ensure_va_cache()
        for r in logs:
            va_name_log = _get_log_va_name(r)
            d = parse_date_loose(safe_get(r, "Post Date"))
            if va_name_log in va_stats:
                if d and d >= today:
                    va_stats[va_name_log]["today"] += 1
                if d and d >= week_start:
                    va_stats[va_name_log]["week"] += 1

        filter_va = " ".join(context.args).strip() if context.args else None

        text = "<b>👥 VA Performance</b>\n━━━━━━━━━━━━━━━━━━\n\n"

        for name, s in sorted(va_stats.items(), key=lambda x: -x[1]["week"]):
            if filter_va and filter_va.lower() != name.lower():
                continue
            ban_rate = s["banned"] / s["accounts"] * 100 if s["accounts"] else 0
            target_met = "✅" if s["expected"] and s["today"] >= s["expected"] else "❌" if s["expected"] else "➖"

            text += (
                f"<b>{name}</b> {target_met}\n"
                f"  Today: {s['today']}"
            )
            if s["expected"]:
                text += f" / {s['expected']} target"
            text += (
                f"\n  Week: {s['week']} posts\n"
                f"  Accs: {s['active']} active / {s['banned']} banned ({ban_rate:.0f}%)\n"
                f"  Karma: {s['karma']:,}\n\n"
            )

        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"vastats error: {e}\n{traceback.format_exc()}")
        await reply(update, f"Error: {e}")


# ── /needaccs ── VAs running low on accounts ──────────────────────────────────

async def needaccs_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        posting = get_table(TABLE_POSTING).all()

        va_active = Counter()
        for r in posting:
            if safe_get(r, "Status") == "Posting":
                va = safe_get(r, "VA", "Unknown")
                va_active[va] += 1

        # Sort by fewest active accounts
        text = "<b>⚠️ Account Levels</b>\n━━━━━━━━━━━━━━━━━━\n\n"
        for va, count in sorted(va_active.items(), key=lambda x: x[1]):
            if va == "Unknown":
                continue
            indicator = "🔴" if count <= 5 else "🟡" if count <= 10 else "🟢"
            text += f"  {indicator} {va}: {count} active accounts\n"

        # Warmup ready
        warmup = get_table(TABLE_WARMUP).all()
        ready = sum(1 for r in warmup if safe_get(r, "Status") == "Warmed Up")
        text += f"\n<b>🎓 Warmed Up & Ready:</b> {ready}\n"

        # Available blanks
        blanks = get_table(TABLE_BLANKS).all()
        available = sum(1 for r in blanks if safe_get(r, "Status") == "Available")
        text += f"<b>🆕 Available Blanks:</b> {available}\n"

        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"needaccs error: {e}\n{traceback.format_exc()}")
        await reply(update, f"Error: {e}")


# ── /daily ── Full daily summary ──────────────────────────────────────────────

async def daily_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await reply(update, "Generating daily report...")
    try:
        blanks = get_table(TABLE_BLANKS).all()
        warmup = get_table(TABLE_WARMUP).all()
        posting = get_table(TABLE_POSTING).all()
        logs = get_table(TABLE_POSTING_LOGS).all()

        today = start_of_today()
        today_str = today.strftime("%Y-%m-%d")

        # Today's posts
        _ensure_va_cache()
        today_logs = []
        va_today = Counter()
        for r in logs:
            d = parse_date_loose(safe_get(r, "Post Date"))
            if d and d >= today:
                today_logs.append(r)
                va_today[_get_log_va_name(r)] += 1

        # Pipeline counts
        b_avail = sum(1 for r in blanks if safe_get(r, "Status") == "Available")
        w_warming = sum(1 for r in warmup if safe_get(r, "Status") == "Warming Up")
        w_ready = sum(1 for r in warmup if safe_get(r, "Status") == "Warmed Up")
        p_active = sum(1 for r in posting if safe_get(r, "Status") == "Posting")
        p_banned = sum(1 for r in posting if safe_get(r, "Status") in ("Banned", "Shadowbanned"))

        # VA target comparison
        vas = get_table(TABLE_VAS).all()
        va_targets = {}
        for v in vas:
            name = safe_get(v, "VA Name")
            expected = safe_get(v, "Expected Posts Per Day", 0)
            if name and expected:
                va_targets[name] = expected

        text = (
            f"<b>📋 Daily Report — {today_str}</b>\n"
            "━━━━━━━━━━━━━━━━━━\n\n"
            f"<b>📝 Posts Today:</b> {len(today_logs)}\n\n"
            "<b>By VA:</b>\n"
        )
        for va, count in va_today.most_common():
            target = va_targets.get(va)
            if target:
                pct = count / target * 100
                text += f"  {va}: {count}/{target} ({pct:.0f}%)\n"
            else:
                text += f"  {va}: {count}\n"

        text += (
            f"\n<b>Pipeline Health:</b>\n"
            f"  🆕 Blanks available: {b_avail}\n"
            f"  ♨️ Warming up: {w_warming}\n"
            f"  🎓 Ready for posting: {w_ready}\n"
            f"  📮 Active posting: {p_active}\n"
            f"  🚫 Banned (posting): {p_banned}\n"
        )

        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"daily error: {e}\n{traceback.format_exc()}")
        await reply(update, f"Error: {e}")


# ── /settopic, /unsettopic, /topics ── Topic configuration ────────────────────

async def settopic_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await reply(update, "Admin only.")

    if len(context.args) < 2:
        return await reply(update, "Usage: /settopic <VA_name> <Model>\nExample: /settopic Lakshit Celes")

    va_name = context.args[0]
    model = context.args[1]
    thread_id = update.message.message_thread_id

    if not thread_id:
        return await reply(update, "Run this command inside a forum topic, not the general chat.")

    chat_id = str(update.effective_chat.id)
    cfg = load_config()
    key = f"{chat_id}:{thread_id}"
    cfg.setdefault("topics", {})[key] = {"va": va_name, "model": model, "thread_id": thread_id, "chat_id": chat_id}
    save_config(cfg)

    await reply(update, f"✅ This topic is now logging for <b>{va_name}</b> [{model}]", parse_mode=ParseMode.HTML)


async def unsettopic_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await reply(update, "Admin only.")

    thread_id = update.message.message_thread_id
    if not thread_id:
        return await reply(update, "Run this inside a forum topic.")

    chat_id = str(update.effective_chat.id)
    cfg = load_config()
    key = f"{chat_id}:{thread_id}"

    if key in cfg.get("topics", {}):
        del cfg["topics"][key]
        save_config(cfg)
        await reply(update, "✅ Topic removed from logging.")
    else:
        await reply(update, "This topic wasn't configured for logging.")


async def topics_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cfg = load_config()
    topics = cfg.get("topics", {})
    if not topics:
        return await reply(update, "No topics configured. Use /settopic <VA> <Model> in a topic.")

    text = "<b>📋 Configured Topics</b>\n━━━━━━━━━━━━━━━━━━\n\n"
    for key, info in topics.items():
        text += f"  Thread {info['thread_id']}: <b>{info['va']}</b> [{info['model']}]\n"

    await reply(update, text, parse_mode=ParseMode.HTML)


# ── /setbanchannel ── Configure ban alert topic ───────────────────────────────

async def setbanchannel_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await reply(update, "Admin only.")

    thread_id = update.message.message_thread_id
    chat_id = str(update.effective_chat.id)

    cfg = load_config()
    cfg["ban_channel"] = {"chat_id": chat_id, "thread_id": thread_id}
    save_config(cfg)

    where = "this topic" if thread_id else "this chat"
    await reply(update, f"✅ Ban alerts will be posted in {where}.")


# ── /setreportchannel ── Configure where periodic reports go ──────────────────

async def setreportchannel_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await reply(update, "Admin only.")

    thread_id = update.message.message_thread_id
    chat_id = str(update.effective_chat.id)

    cfg = load_config()
    cfg["report_channel"] = {"chat_id": chat_id, "thread_id": thread_id}
    save_config(cfg)

    where = "this topic" if thread_id else "this chat"
    await reply(update, f"✅ Activity reports will be posted in {where}.")


# ── /linkva ── Link Telegram user to VA name ──────────────────────────────────

async def linkva_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await reply(update, "Admin only.")

    if not context.args:
        return await reply(update, "Usage: /linkva <VA_name> (reply to the VA's message)")

    va_name = " ".join(context.args).strip()
    users = extract_user_ids_from_message(update)

    if not users:
        return await reply(update, "Reply to the VA's message to link them.")

    user_id = str(users[0][0])
    display_name = users[0][1]

    cfg = load_config()
    cfg.setdefault("va_map", {})[user_id] = va_name
    save_config(cfg)

    await reply(update, f"✅ Linked {display_name} → <b>{va_name}</b>", parse_mode=ParseMode.HTML)


# ── Auto link detection ── Reddit URL message handler ─────────────────────────

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return

    thread_id = update.message.message_thread_id
    if not thread_id:
        return  # Only process messages in forum topics

    chat_id = str(update.effective_chat.id)
    topic_cfg = get_topic_config(chat_id, thread_id)
    if not topic_cfg:
        return  # Not a configured logging topic

    # Find Reddit URLs in the message
    urls = REDDIT_URL_PATTERN.findall(update.message.text)
    if not urls:
        return

    va_name = topic_cfg["va"]
    model = topic_cfg["model"]

    # Check for duplicates and log each URL
    cfg = load_config()
    logged_urls = set()
    existing_logs = None  # Lazy load

    results = []
    for url in urls:
        url = url.strip()

        # Check for duplicate
        if existing_logs is None:
            try:
                existing_logs = get_table(TABLE_POSTING_LOGS).all()
                logged_urls = {safe_get(r, "Post URL", "").strip().lower() for r in existing_logs}
            except Exception:
                logged_urls = set()

        if url.lower() in logged_urls:
            results.append(f"⚠️ Duplicate: {url}")
            continue

        # Validate it's a post URL (not just a user profile)
        if "/comments/" not in url and "/s/" not in url:
            results.append(f"⚠️ Not a post URL: {url}")
            continue

        # Find the Reddit account in Posting table
        reddit_account_id = None
        try:
            posting_records = get_table(TABLE_POSTING).all()
            # Try to extract subreddit username from post URL isn't reliable
            # Instead, we just log with VA info
        except Exception:
            pass

        # Create the posting log record
        try:
            record_data = {"Post URL": url}
            # Link to VA record if possible
            try:
                vas_table = get_table(TABLE_VAS).all()
                for v in vas_table:
                    if safe_get(v, "VA Name") == va_name:
                        record_data["VAs"] = [v["id"]]
                        break
            except Exception:
                pass

            get_table(TABLE_POSTING_LOGS).create(record_data)
            results.append(f"✅ Logged: {url}")
            logged_urls.add(url.lower())  # Prevent duplicate within same message
        except Exception as e:
            results.append(f"❌ Failed: {url} — {e}")
            logger.error(f"Log post error: {e}")

    if results:
        key = (chat_id, thread_id)
        for r in results:
            _pending_post_logs[key].append((va_name, model, r))


async def flush_post_logs(context: ContextTypes.DEFAULT_TYPE):
    """Send batched post log summaries every few hours."""
    if not _pending_post_logs:
        return

    pending = dict(_pending_post_logs)
    _pending_post_logs.clear()

    for (chat_id, thread_id), entries in pending.items():
        # Group by VA name + model
        by_va: dict[str, list[str]] = defaultdict(list)
        for va_name, model, line in entries:
            by_va[f"{va_name} [{model}]"].append(line)

        lines = []
        for va_label, logs in by_va.items():
            lines.append(f"<b>📝 {va_label}</b>")
            lines.extend(logs)
            lines.append("")

        text = f"<b>📋 Post Log Summary — {len(entries)} posts</b>\n\n" + "\n".join(lines)

        try:
            kwargs = {
                "chat_id": int(chat_id),
                "text": text,
                "parse_mode": ParseMode.HTML,
                "disable_notification": True,
            }
            if thread_id:
                kwargs["message_thread_id"] = thread_id
            await context.bot.send_message(**kwargs)
        except Exception as e:
            logger.error(f"Failed to flush post logs: {e}")


async def post_activity_report(context: ContextTypes.DEFAULT_TYPE):
    """Send a periodic activity report to the configured report channel."""
    cfg = load_config()
    report_channel = cfg.get("report_channel")
    if not report_channel:
        return

    try:
        logs = get_table(TABLE_POSTING_LOGS).all()
        posting = get_table(TABLE_POSTING).all()
        _ensure_va_cache()

        now = now_utc()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)

        # Posts in last 24h
        posts_24h = []
        for r in logs:
            d = parse_date_loose(safe_get(r, "Post Date"))
            if d and d >= last_24h:
                posts_24h.append(r)

        # Posts in last 7 days
        posts_7d = []
        for r in logs:
            d = parse_date_loose(safe_get(r, "Post Date"))
            if d and d >= last_7d:
                posts_7d.append(r)

        # Per-VA breakdown (last 24h)
        va_24h = Counter()
        for r in posts_24h:
            va_24h[_get_log_va_name(r)] += 1

        # Account stats
        active_accounts = [r for r in posting if safe_get(r, "Status") in ("Posting", "Dormant")]
        banned_accounts = [r for r in posting if safe_get(r, "Status") in ("Banned", "Shadowbanned")]

        # Build report
        text = "<b>📊 Activity Report</b>\n━━━━━━━━━━━━━━━━━━\n\n"

        text += f"<b>Last 24 hours:</b> {len(posts_24h)} posts\n"
        text += f"<b>Last 7 days:</b> {len(posts_7d)} posts\n"
        text += f"<b>Total logged:</b> {len(logs)} posts\n\n"

        if va_24h:
            text += "<b>📝 Posts by VA (24h):</b>\n"
            for va, count in va_24h.most_common():
                text += f"  {va}: {count}\n"
            text += "\n"

        text += f"<b>👥 Accounts:</b>\n"
        text += f"  Active: {len(active_accounts)}\n"
        text += f"  Banned: {len(banned_accounts)}\n"

        # Avg posts per day (last 7 days)
        if posts_7d:
            avg = len(posts_7d) / 7
            text += f"\n<b>📈 Avg posts/day (7d):</b> {avg:.1f}"

        chat_id = report_channel["chat_id"]
        thread_id = report_channel.get("thread_id")
        kwargs = {
            "chat_id": int(chat_id),
            "text": text,
            "parse_mode": ParseMode.HTML,
        }
        if thread_id:
            kwargs["message_thread_id"] = thread_id
        await context.bot.send_message(**kwargs)

    except Exception as e:
        logger.error(f"Activity report error: {e}\n{traceback.format_exc()}")


# ── Ban alert polling ─────────────────────────────────────────────────────────

async def poll_bans(context: ContextTypes.DEFAULT_TYPE):
    """Periodic job that checks for newly banned accounts and sends alerts."""
    cfg = load_config()
    ban_channel = cfg.get("ban_channel")

    known_bans = set(cfg.get("known_bans", []))
    is_first_run = not cfg.get("bans_seeded", False)

    try:
        # Check all three tables for banned accounts
        tables_to_check = [
            (TABLE_BLANKS, "Blanks Creation", ["Banned"]),
            (TABLE_WARMUP, "Warmup", ["Banned", "Taken&Banned"]),
            (TABLE_POSTING, "Posting", ["Banned", "Shadowbanned"]),
        ]

        new_bans = []
        for table_id, stage, ban_statuses in tables_to_check:
            records = get_table(table_id).all()
            for r in records:
                status = safe_get(r, "Status")
                username = safe_get(r, "Reddit Username")
                if not username or status not in ban_statuses:
                    continue

                ban_key = f"{table_id}:{username}"
                if ban_key in known_bans:
                    continue

                # Add to known set
                known_bans.add(ban_key)

                # On first run, just seed the known list — don't alert
                if is_first_run:
                    continue

                info = {
                    "username": username,
                    "stage": stage,
                    "status": status,
                    "va": safe_get(r, "VA", "N/A"),
                    "model": safe_get(r, "Model", "N/A"),
                    "post_karma": safe_get(r, "Post Karma", "0"),
                    "comment_karma": safe_get(r, "Comment Karma", "0"),
                    "account_age": safe_get(r, "Account Age", "N/A"),
                    "location": safe_get(r, "Location", "N/A"),
                    "proxy": safe_get(r, "Proxy Used", "—"),
                }
                new_bans.append(info)

        # Save updated known bans + mark as seeded
        cfg["known_bans"] = list(known_bans)
        cfg["bans_seeded"] = True
        save_config(cfg)

        if is_first_run:
            logger.info(f"Ban tracker seeded with {len(known_bans)} existing bans (no alerts sent)")
            return

        # Send alerts (only if ban channel is configured)
        if new_bans and ban_channel:
            chat_id = ban_channel["chat_id"]
            thread_id = ban_channel.get("thread_id")

            # Batch into a single message to avoid spamming
            timestamp = now_ist().strftime('%Y-%m-%d %I:%M %p IST')
            text = f"<b>🚫 {len(new_bans)} New Ban{'s' if len(new_bans) != 1 else ''} Detected</b>\n"
            text += f"<i>{timestamp}</i>\n━━━━━━━━━━━━━━━━━━\n\n"

            for ban in new_bans[:20]:  # cap at 20 to avoid message too long
                try:
                    pk = int(ban["post_karma"]) if ban["post_karma"] else 0
                except (ValueError, TypeError):
                    pk = 0
                try:
                    ck = int(ban["comment_karma"]) if ban["comment_karma"] else 0
                except (ValueError, TypeError):
                    ck = 0
                total_karma = pk + ck
                status_emoji = "👻" if ban["status"] == "Shadowbanned" else "🚫"
                proxy_val = ban.get("proxy", "").strip()
                if proxy_val and proxy_val != "—":
                    proxy_str = f"🔒 Proxy: {proxy_val}"
                else:
                    proxy_str = "⚠️ Proxy not mentioned"
                loc_str = f" | {ban['location']}" if ban.get("location") and ban["location"] != "N/A" else ""
                text += (
                    f"{status_emoji} <b>u/{ban['username']}</b>\n"
                    f"   📍 Stage: {ban['stage']} | {ban['va']} | {ban['model']}{loc_str}\n"
                    f"   {proxy_str}\n"
                    f"   Karma: {total_karma:,} | Age: {ban['account_age']}\n\n"
                )
            if len(new_bans) > 20:
                text += f"<i>...and {len(new_bans) - 20} more</i>\n"

            kwargs = {"chat_id": int(chat_id), "text": text, "parse_mode": ParseMode.HTML}
            if thread_id:
                kwargs["message_thread_id"] = thread_id
            try:
                await context.bot.send_message(**kwargs)
            except Exception as e:
                logger.error(f"Failed to send ban alert: {e}")
        elif new_bans:
            logger.info(f"{len(new_bans)} new bans detected but no ban channel configured")

    except Exception as e:
        logger.error(f"Ban poll error: {e}\n{traceback.format_exc()}")


# ── Weekly leaderboard (scheduled) ────────────────────────────────────────────

async def weekly_leaderboard(context: ContextTypes.DEFAULT_TYPE):
    """Sends weekly leaderboard to ban channel (reuses the configured chat)."""
    cfg = load_config()
    ban_channel = cfg.get("ban_channel")
    if not ban_channel:
        return

    chat_id = ban_channel["chat_id"]

    try:
        logs = get_table(TABLE_POSTING_LOGS).all()
        week_start = start_of_week()

        _ensure_va_cache()
        va_counts = Counter()
        for r in logs:
            d = parse_date_loose(safe_get(r, "Post Date"))
            if d and d >= week_start:
                va_counts[_get_log_va_name(r)] += 1

        if not va_counts:
            return

        text = "<b>🏆 Weekly Leaderboard</b>\n━━━━━━━━━━━━━━━━━━\n\n"
        medals = ["🥇", "🥈", "🥉"]
        for i, (va, count) in enumerate(va_counts.most_common()):
            medal = medals[i] if i < 3 else f"  {i+1}."
            text += f"{medal} {va}: {count} posts\n"

        kwargs = {"chat_id": int(chat_id), "text": text, "parse_mode": ParseMode.HTML}
        thread_id = ban_channel.get("thread_id")
        if thread_id:
            kwargs["message_thread_id"] = thread_id
        await context.bot.send_message(**kwargs)
    except Exception as e:
        logger.error(f"Leaderboard error: {e}\n{traceback.format_exc()}")


# ── Role management commands (preserved) ──────────────────────────────────────

async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "<b>Kernel Ops</b>\n"
        "━━━━━━━━━━━━━━━━━━\n\n"
        "<b>Pipeline</b>\n"
        "  /status — Full overview\n"
        "  /daily — Complete daily report\n"
        "  /blanks — Blank accounts\n"
        "  /warmup — Warmup progress\n"
        "  /posting — Posting accounts\n"
        "  /bans — Banned accounts\n"
        "  /logs — Posting logs\n"
        "  /accounts [model] — Per-model breakdown\n"
        "  /needaccs — VAs low on accounts\n\n"
        "<b>Account Tools</b>\n"
        "  /refresh — Update karma/age from Reddit\n"
        "  /checkbans — Scan all stages for Reddit bans\n"
        "  /postcheck — Shadowban checker\n"
        "  /topaccs — Highest karma accounts\n"
        "  /warnings — Accounts needing attention\n\n"
        "<b>Analytics</b>\n"
        "  /postaudit — Check if posts got removed\n"
        "  /heatmap — Engagement heatmap\n"
        "  /optimize — Portfolio optimizer\n"
        "  /deadsubs — Find dead subreddits\n\n"
        "<b>Reddit Intel</b>\n"
        "  /sub &lt;subreddit&gt; — Subreddit intel\n"
        "  /reqs &lt;subreddit&gt; — Posting requirements\n"
        "  /hot &lt;subreddit&gt; — Hot posts\n"
        "  /profile &lt;user&gt; — Reddit user profile\n"
        "  /similar &lt;subreddit&gt; — Find similar subs\n"
        "  /nsfw &lt;query&gt; — Search NSFW subs\n"
        "  /bulk — Analyze multiple subs\n"
        "  /modscan &lt;subreddit&gt; — Mod activity scan\n"
        "  /plan &lt;subreddit&gt; — Infiltration plan\n\n"
        "<b>VA Stats</b>\n"
        "  /mystats — Your personal stats\n"
        "  /vastats [name] — VA dashboard (admin)\n\n"
        "<b>Config (admin)</b>\n"
        "  /settopic &lt;VA&gt; &lt;Model&gt; — Auto-logging topic\n"
        "  /unsettopic — Remove topic logging\n"
        "  /topics — List configured topics\n"
        "  /setbanchannel — Ban alert topic\n"
        "  /setreportchannel — Activity report topic\n"
        "  /linkva &lt;name&gt; — Link user to VA\n\n"
        "<b>Roles</b>\n"
        "  /createrole &lt;name&gt; — Create a role\n"
        "  /deleterole &lt;name&gt; — Delete a role\n"
        "  /assign &lt;role&gt; — Assign role\n"
        "  /unassign &lt;role&gt; — Remove role\n"
        "  /roles — List all roles\n"
        "  /myroles — Your roles\n"
        "  /tag &lt;role&gt; — Ping role members\n"
    )
    await reply(update, text, parse_mode=ParseMode.HTML)


async def createrole(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await reply(update, "Only admins can create roles.")
    if not context.args:
        return await reply(update, "Usage: /createrole <name>")
    role = " ".join(context.args).strip().lower()
    chat_id = str(update.effective_chat.id)
    data, chat = get_chat_data(chat_id)
    if role in chat["roles"]:
        return await reply(update, f"Role '{role}' already exists.")
    chat["roles"].append(role)
    save_roles_data(data)
    await reply(update, f"✅ Role '{role}' created.")


async def deleterole(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await reply(update, "Only admins can delete roles.")
    if not context.args:
        return await reply(update, "Usage: /deleterole <name>")
    role = " ".join(context.args).strip().lower()
    chat_id = str(update.effective_chat.id)
    data, chat = get_chat_data(chat_id)
    if role not in chat["roles"]:
        return await reply(update, f"Role '{role}' doesn't exist.")
    chat["roles"].remove(role)
    for uid in chat["assignments"]:
        if role in chat["assignments"][uid]:
            chat["assignments"][uid].remove(role)
    save_roles_data(data)
    await reply(update, f"✅ Role '{role}' deleted.")


async def assign(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await reply(update, "Only admins can assign roles.")
    if not context.args:
        return await reply(update, "Usage: /assign <role> @user or user_id ...")
    role = context.args[0].strip().lower()
    chat_id = str(update.effective_chat.id)
    data, chat = get_chat_data(chat_id)
    if role not in chat["roles"]:
        return await reply(update, f"Role '{role}' doesn't exist.")

    # Collect users from mentions / reply
    users = extract_user_ids_from_message(update)

    # Also collect raw numeric user IDs from args (e.g. /assign all 123 456 789)
    for arg in context.args[1:]:
        if arg.isdigit() and int(arg) not in {u[0] for u in users}:
            uid = int(arg)
            # Try to resolve name from Telegram
            try:
                member = await context.bot.get_chat_member(update.effective_chat.id, uid)
                name = member.user.first_name or str(uid)
                _cache_user(member.user)
            except Exception:
                name = str(uid)
            users.append((uid, name))

    if not users:
        return await reply(update, "Mention users, reply, or pass user IDs.")
    assigned, already = [], []
    for uid, name in users:
        uid_str = str(uid)
        if uid_str not in chat["assignments"]:
            chat["assignments"][uid_str] = []
        if role in chat["assignments"][uid_str]:
            already.append(name)
        else:
            chat["assignments"][uid_str].append(role)
            assigned.append(name)
    save_roles_data(data)
    parts = []
    if assigned:
        parts.append(f"Assigned '{role}' to: {', '.join(assigned)}")
    if already:
        parts.append(f"Already had role: {', '.join(already)}")
    await reply(update, "\n".join(parts) if parts else "No changes.")


async def unassign(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await reply(update, "Only admins can remove roles.")
    if not context.args:
        return await reply(update, "Usage: /unassign <role> @user or user_id ...")
    role = context.args[0].strip().lower()
    chat_id = str(update.effective_chat.id)
    data, chat = get_chat_data(chat_id)

    users = extract_user_ids_from_message(update)
    for arg in context.args[1:]:
        if arg.isdigit() and int(arg) not in {u[0] for u in users}:
            uid = int(arg)
            try:
                member = await context.bot.get_chat_member(update.effective_chat.id, uid)
                name = member.user.first_name or str(uid)
            except Exception:
                name = str(uid)
            users.append((uid, name))

    if not users:
        return await reply(update, "Mention users, reply, or pass user IDs.")
    removed, not_had = [], []
    for uid, name in users:
        uid_str = str(uid)
        if uid_str in chat["assignments"] and role in chat["assignments"][uid_str]:
            chat["assignments"][uid_str].remove(role)
            removed.append(name)
        else:
            not_had.append(name)
    save_roles_data(data)
    parts = []
    if removed:
        parts.append(f"Removed '{role}' from: {', '.join(removed)}")
    if not_had:
        parts.append(f"Didn't have role: {', '.join(not_had)}")
    await reply(update, "\n".join(parts) if parts else "No changes.")


async def roles_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    _, chat = get_chat_data(chat_id)
    if not chat["roles"]:
        return await reply(update, "No roles yet. Use /createrole <name>.")
    await reply(update, "Roles:\n" + "\n".join(f"  - {r}" for r in sorted(chat["roles"])))


async def myroles(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    uid = str(update.effective_user.id)
    _, chat = get_chat_data(chat_id)
    user_roles = chat["assignments"].get(uid, [])
    if not user_roles:
        return await reply(update, "You have no roles.")
    await reply(update, "Your roles:\n" + "\n".join(f"  - {r}" for r in sorted(user_roles)))


async def tag(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await reply(update, "Usage: /tag <role>")
    role = " ".join(context.args).strip().lower()
    chat_id = str(update.effective_chat.id)
    _, chat = get_chat_data(chat_id)
    if role not in chat["roles"]:
        return await reply(update, f"Role '{role}' doesn't exist.")
    user_ids = [uid for uid, r_list in chat["assignments"].items() if role in r_list]
    if not user_ids:
        return await reply(update, f"No one has the '{role}' role.")
    mentions = []
    for uid in user_ids:
        try:
            member = await context.bot.get_chat_member(int(chat_id), int(uid))
            name = member.user.first_name or "User"
        except Exception:
            name = "User"
        mentions.append(f'<a href="tg://user?id={uid}">{name}</a>')
    text = f"<b>{role}</b>: " + " ".join(mentions)
    try:
        kwargs = dict(chat_id=update.effective_chat.id, text=text, parse_mode=ParseMode.HTML)
        if update.message and update.message.message_thread_id:
            kwargs["message_thread_id"] = update.message.message_thread_id
        await context.bot.send_message(**kwargs)
    except Exception as e:
        logger.error(f"Tag send failed: {e}")
        # Fallback without HTML in case formatting caused the issue
        plain = f"{role}: " + ", ".join(f"User {uid}" for uid in user_ids)
        await reply(update, plain)


# ── Analytics helpers ─────────────────────────────────────────────────────────

def _sub_from_url(url: str) -> str | None:
    """Extract subreddit name from a reddit post URL."""
    m = re.search(r"reddit\.com/r/(\w+)", url, re.IGNORECASE)
    return m.group(1).lower() if m else None


async def _reddit_get(url: str, timeout: int = 15) -> dict | None:
    """Quick Reddit JSON GET with user-agent."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                url,
                headers={"User-Agent": REDDIT_USER_AGENT},
                follow_redirects=True,
                timeout=timeout,
            )
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return None


async def _check_post_alive(post_url: str) -> str:
    """Check if a Reddit post is still live. Returns status string."""
    # Convert share links and normalize
    clean = post_url.strip().rstrip("/")
    # Need the .json endpoint
    if "/comments/" in clean:
        json_url = clean + ".json"
    elif "/s/" in clean:
        # Share links — try to follow redirect
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(clean, headers={"User-Agent": REDDIT_USER_AGENT}, follow_redirects=True, timeout=10)
                if resp.status_code == 200 and "/comments/" in str(resp.url):
                    json_url = str(resp.url).rstrip("/") + ".json"
                else:
                    return "unknown"
        except Exception:
            return "unknown"
    else:
        return "unknown"

    data = await _reddit_get(json_url)
    if not data:
        return "dead"
    try:
        post_data = data[0]["data"]["children"][0]["data"]
        if post_data.get("removed_by_category"):
            return "removed"
        if post_data.get("selftext") == "[removed]":
            return "removed"
        if post_data.get("selftext") == "[deleted]":
            return "deleted"
        if post_data.get("author") in ("[deleted]", None):
            return "deleted"
        return "live"
    except (IndexError, KeyError, TypeError):
        return "unknown"


# ── /postaudit — Post Removal Detector ───────────────────────────────────────

async def postaudit_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Check which recent logged posts are still live vs removed."""
    arg = (context.args[0].lower() if context.args else "").strip()
    check_count = 30
    if arg.isdigit():
        check_count = min(int(arg), 60)

    msg = await update.message.reply_text(
        f"Checking last {check_count} logged posts...\n"
        "<i>Verifying each post is still live on Reddit</i>",
        parse_mode=ParseMode.HTML,
    )

    try:
        logs = get_table(TABLE_POSTING_LOGS).all()
        _ensure_va_cache()

        # Sort by date descending, take recent ones
        dated_logs = []
        for r in logs:
            d = parse_date_loose(safe_get(r, "Post Date"))
            url = safe_get(r, "Post URL", "").strip()
            if d and url:
                dated_logs.append({"date": d, "url": url, "va": _get_log_va_name(r), "record": r})
        dated_logs.sort(key=lambda x: x["date"], reverse=True)
        to_check = dated_logs[:check_count]

        if not to_check:
            return await msg.edit_text("No recent posts found in logs.")

        live = []
        removed = []
        deleted = []
        unknown = []

        for i, entry in enumerate(to_check):
            if i > 0 and i % 10 == 0:
                try:
                    await msg.edit_text(
                        f"Checking posts... ({i}/{len(to_check)})",
                        parse_mode=ParseMode.HTML,
                    )
                except Exception:
                    pass
            status = await _check_post_alive(entry["url"])
            sub = _sub_from_url(entry["url"]) or "?"
            entry_info = {"va": entry["va"], "sub": sub, "url": entry["url"][:50], "date": entry["date"]}

            if status == "live":
                live.append(entry_info)
            elif status == "removed":
                removed.append(entry_info)
            elif status == "deleted":
                deleted.append(entry_info)
            else:
                unknown.append(entry_info)
            await asyncio.sleep(1.5)  # Rate limit

        total = len(to_check)
        live_pct = round(len(live) / total * 100) if total else 0

        text = (
            f"<b>📋 Post Audit — {total} posts checked</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n\n"
            f"✅ Live: <b>{len(live)}</b> ({live_pct}%)\n"
            f"🗑 Removed: <b>{len(removed)}</b>\n"
            f"💀 Deleted: <b>{len(deleted)}</b>\n"
            f"❓ Unknown: <b>{len(unknown)}</b>\n\n"
        )

        if removed:
            text += "<b>🗑 Removed Posts</b>\n"
            # Group by sub
            rm_by_sub = Counter(r["sub"] for r in removed)
            for sub, count in rm_by_sub.most_common():
                text += f"  r/{sub}: {count} removed\n"
            text += "\n"
            for r in removed[:10]:
                text += f"  • {r['va']} — r/{r['sub']}\n"
            if len(removed) > 10:
                text += f"  <i>...+{len(removed) - 10} more</i>\n"
            text += "\n"

        # VA removal rates
        va_total = Counter()
        va_removed = Counter()
        for e in live:
            va_total[e["va"]] += 1
        for e in removed + deleted:
            va_total[e["va"]] += 1
            va_removed[e["va"]] += 1
        for e in unknown:
            va_total[e["va"]] += 1

        if va_removed:
            text += "<b>⚠️ Removal Rate by VA</b>\n"
            for va in sorted(va_removed, key=lambda v: va_removed[v] / max(va_total[v], 1), reverse=True):
                rate = round(va_removed[va] / max(va_total[va], 1) * 100)
                text += f"  {va}: {va_removed[va]}/{va_total[va]} removed ({rate}%)\n"
            text += "\n"

        text += f"<i>Use /postaudit [count] to check more posts</i>"

        await msg.delete()
        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"postaudit error: {e}\n{traceback.format_exc()}")
        await msg.edit_text(f"Error: {e}")


# ── /plan — Sub Infiltration Planner ─────────────────────────────────────────

async def plan_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Full attack plan for infiltrating a subreddit."""
    if not context.args:
        return await reply(update, "Usage: <code>/plan subreddit_name</code>", parse_mode=ParseMode.HTML)

    sub = context.args[0].strip().lstrip("r/").lstrip("/")
    msg = await update.message.reply_text(
        f"Building infiltration plan for r/{sub}...\n"
        "<i>Scanning posts, rules, and profiling users</i>",
        parse_mode=ParseMode.HTML,
    )

    try:
        # Fetch everything in sequence (rate limited anyway)
        info_data = await _reddit_get(f"https://www.reddit.com/r/{sub}/about.json")
        if not info_data or info_data.get("_error"):
            return await msg.edit_text(f"Could not find r/{sub}.")

        info = info_data.get("data", {})
        nsfw = info.get("over18", False)
        subs_count = info.get("subscribers", 0)
        online = info.get("accounts_active", 0)

        # Fetch rules
        rules_data = await _reddit_get(f"https://www.reddit.com/r/{sub}/about/rules.json")
        rules = rules_data.get("rules", []) if rules_data else []

        # Fetch recent posts to find floor + timing
        await asyncio.sleep(2)
        posts_data = await _reddit_get(f"https://www.reddit.com/r/{sub}/new.json?limit=50")
        posts = []
        if posts_data:
            for child in posts_data.get("data", {}).get("children", []):
                p = child.get("data", {})
                posts.append(p)

        # Fetch hot posts for engagement data
        await asyncio.sleep(2)
        hot_data = await _reddit_get(f"https://www.reddit.com/r/{sub}/hot.json?limit=25")
        hot_posts = []
        if hot_data:
            for child in hot_data.get("data", {}).get("children", []):
                hot_posts.append(child.get("data", {}))

        # Analyze post timing (hour distribution)
        hour_counts = Counter()
        content_types = Counter()
        flair_counts = Counter()
        for p in posts:
            ts = p.get("created_utc", 0)
            if ts:
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                hour_counts[dt.hour] += 1
            # Content type
            if p.get("is_video"):
                content_types["Video"] += 1
            elif p.get("is_gallery"):
                content_types["Gallery"] += 1
            elif p.get("post_hint") == "image":
                content_types["Image"] += 1
            elif p.get("is_self"):
                content_types["Text"] += 1
            else:
                content_types["Link/Other"] += 1
            # Flairs
            flair = p.get("link_flair_text")
            if flair:
                flair_counts[flair] += 1

        # Find lowest karma poster
        lowest_karma = None
        newest_acc = None
        users_checked = 0
        seen_users = set()
        for p in posts[:20]:
            author = p.get("author", "[deleted]")
            if author in ("[deleted]", "AutoModerator", "[removed]") or author in seen_users:
                continue
            seen_users.add(author)
            await asyncio.sleep(2)
            profile = await fetch_reddit_profile(author)
            if not profile or profile.get("suspended") or profile.get("rate_limited"):
                continue
            users_checked += 1
            tk = profile["total_karma"]
            if lowest_karma is None or tk < lowest_karma["karma"]:
                lowest_karma = {"user": author, "karma": tk, "age": profile.get("account_age", "?")}
            created = profile.get("date_of_creation", "9999")
            if newest_acc is None or (created and created > (newest_acc.get("created") or "")):
                newest_acc = {"user": author, "karma": tk, "age": profile.get("account_age", "?"), "created": created}

            if users_checked >= 10:
                break

        # Best posting hours
        best_hours = hour_counts.most_common(3)

        # Engagement from hot posts
        avg_score = 0
        avg_comments = 0
        if hot_posts:
            avg_score = sum(p.get("score", 0) for p in hot_posts) // len(hot_posts)
            avg_comments = sum(p.get("num_comments", 0) for p in hot_posts) // len(hot_posts)

        # Check which of our accounts can post there
        posting_records = get_table(TABLE_POSTING).all()
        eligible = []
        not_eligible = []
        min_karma = lowest_karma["karma"] if lowest_karma else 0

        for r in posting_records:
            if safe_get(r, "Status") != "Posting":
                continue
            uname = safe_get(r, "Reddit Username", "").strip()
            if not uname:
                continue
            try:
                pk = int(safe_get(r, "Post Karma", "0") or 0)
                ck = int(safe_get(r, "Comment Karma", "0") or 0)
            except (ValueError, TypeError):
                pk, ck = 0, 0
            total = pk + ck
            va = safe_get(r, "VA", "?")

            if total >= min_karma:
                eligible.append({"user": uname, "karma": total, "va": va})
            else:
                not_eligible.append({"user": uname, "karma": total, "va": va, "needs": min_karma - total})

        # Build output
        nsfw_tag = " [NSFW]" if nsfw else ""
        text = (
            f"<b>🎯 Infiltration Plan — r/{sub}</b>{nsfw_tag}\n"
            f"━━━━━━━━━━━━━━━━━━\n\n"
            f"<b>Sub Info</b>\n"
            f"  Members: {subs_count:,}  |  Online: {online:,}\n"
            f"  Avg hot post: {avg_score:,} upvotes / {avg_comments} comments\n\n"
        )

        # Floor
        text += "<b>📊 Posting Floor</b>\n"
        if lowest_karma:
            text += f"  Min karma seen: <b>{lowest_karma['karma']:,}</b> (u/{lowest_karma['user']} — {lowest_karma['age']})\n"
        if newest_acc and (not lowest_karma or newest_acc["user"] != lowest_karma["user"]):
            text += f"  Newest account: <b>{newest_acc['age']}</b> (u/{newest_acc['user']} — {newest_acc['karma']:,} karma)\n"
        text += "\n"

        # Best times
        if best_hours:
            text += "<b>⏰ Best Posting Times (UTC)</b>\n"
            for hour, count in best_hours:
                bar = "█" * min(count, 10)
                text += f"  {hour:02d}:00 — {bar} ({count} posts)\n"
            text += "\n"

        # Content types
        if content_types:
            text += "<b>📎 Content Types</b>\n"
            for ctype, count in content_types.most_common():
                text += f"  {ctype}: {count}\n"
            text += "\n"

        # Flairs
        if flair_counts:
            text += "<b>🏷 Active Flairs</b>\n"
            for flair, count in flair_counts.most_common(8):
                text += f"  {flair} ({count})\n"
            text += "\n"

        # Rules summary
        if rules:
            text += f"<b>📜 Rules ({len(rules)})</b>\n"
            for r in rules[:8]:
                text += f"  • {r.get('short_name', '?')[:60]}\n"
            text += "\n"

        # Eligible accounts
        text += f"<b>✅ Eligible Accounts ({len(eligible)})</b>\n"
        if eligible:
            eligible.sort(key=lambda x: x["karma"])
            for a in eligible[:10]:
                text += f"  u/{a['user']} — {a['karma']:,} karma ({a['va']})\n"
            if len(eligible) > 10:
                text += f"  <i>...+{len(eligible) - 10} more</i>\n"
        else:
            text += "  None of your accounts meet the floor\n"

        if not_eligible:
            text += f"\n<b>❌ Not Eligible ({len(not_eligible)})</b>\n"
            not_eligible.sort(key=lambda x: x["needs"])
            for a in not_eligible[:5]:
                text += f"  u/{a['user']} — {a['karma']:,} karma (needs +{a['needs']:,})\n"

        await msg.delete()
        await reply(update, text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except Exception as e:
        logger.error(f"plan error: {e}\n{traceback.format_exc()}")
        await msg.edit_text(f"Error: {e}")


# ── /optimize — Account Portfolio Optimizer ──────────────────────────────────

async def optimize_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Find accounts wasted on easy subs that could hit harder ones."""
    msg = await update.message.reply_text(
        "Analyzing account portfolio...\n"
        "<i>Cross-referencing accounts, logs, and sub floors</i>",
        parse_mode=ParseMode.HTML,
    )

    try:
        posting = get_table(TABLE_POSTING).all()
        logs = get_table(TABLE_POSTING_LOGS).all()
        _ensure_va_cache()

        active = [r for r in posting if safe_get(r, "Status") == "Posting"]
        if not active:
            return await msg.edit_text("No active posting accounts found.")

        # Build account karma map
        accounts = {}
        for r in active:
            uname = safe_get(r, "Reddit Username", "").strip()
            if not uname:
                continue
            try:
                pk = int(safe_get(r, "Post Karma", "0") or 0)
                ck = int(safe_get(r, "Comment Karma", "0") or 0)
            except (ValueError, TypeError):
                pk, ck = 0, 0
            accounts[uname.lower()] = {
                "username": uname,
                "karma": pk + ck,
                "va": safe_get(r, "VA", "?"),
                "model": safe_get(r, "Model", "?"),
                "subs": set(),
            }

        # Map accounts to subs from posting logs
        for r in logs:
            url = safe_get(r, "Post URL", "")
            sub = _sub_from_url(url)
            va_name = _get_log_va_name(r)
            if sub:
                # Try to match by VA name or URL content
                for uname, acc in accounts.items():
                    if acc["va"] == va_name:
                        acc["subs"].add(sub)

        # Find accounts with high karma only posting to easy subs
        # Sort accounts by karma descending
        sorted_accs = sorted(accounts.values(), key=lambda x: x["karma"], reverse=True)

        overqualified = []
        underutilized = []
        no_posts = []

        for acc in sorted_accs:
            if not acc["subs"]:
                if acc["karma"] > 100:
                    no_posts.append(acc)
                continue

            # High karma accounts on low-tier subs
            if acc["karma"] >= 1000 and len(acc["subs"]) <= 3:
                overqualified.append(acc)
            elif acc["karma"] >= 500 and len(acc["subs"]) <= 1:
                underutilized.append(acc)

        text = (
            f"<b>📈 Portfolio Optimizer — {len(accounts)} accounts</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n\n"
        )

        # Karma tiers
        tiers = {"🏆 High (1k+)": 0, "📈 Mid (100-999)": 0, "📉 Low (<100)": 0}
        for acc in accounts.values():
            if acc["karma"] >= 1000:
                tiers["🏆 High (1k+)"] += 1
            elif acc["karma"] >= 100:
                tiers["📈 Mid (100-999)"] += 1
            else:
                tiers["📉 Low (<100)"] += 1

        text += "<b>Karma Distribution</b>\n"
        for tier, count in tiers.items():
            text += f"  {tier}: {count}\n"
        text += "\n"

        # Overqualified accounts
        if overqualified:
            text += f"<b>⚡ High Karma, Few Subs ({len(overqualified)})</b>\n"
            text += "<i>These accounts could handle harder subs</i>\n"
            for acc in overqualified[:8]:
                subs_str = ", ".join(f"r/{s}" for s in list(acc["subs"])[:3])
                text += f"  u/{acc['username']} — <b>{acc['karma']:,}</b> karma\n"
                text += f"    Posts to: {subs_str}\n"
                text += f"    VA: {acc['va']}\n\n"

        # Underutilized
        if underutilized:
            text += f"<b>💤 Underutilized ({len(underutilized)})</b>\n"
            text += "<i>Mid karma but barely posting</i>\n"
            for acc in underutilized[:5]:
                subs_str = ", ".join(f"r/{s}" for s in list(acc["subs"])[:3])
                text += f"  u/{acc['username']} — {acc['karma']:,} karma → {subs_str}\n"
            text += "\n"

        # Accounts with karma but no logged posts
        if no_posts:
            text += f"<b>🔇 No Recent Posts ({len(no_posts)})</b>\n"
            text += "<i>Active accounts with karma but no logged posts</i>\n"
            for acc in no_posts[:8]:
                text += f"  u/{acc['username']} — {acc['karma']:,} karma ({acc['va']})\n"
            text += "\n"

        # Top accounts by karma
        text += "<b>💎 Top 10 by Karma</b>\n"
        for acc in sorted_accs[:10]:
            sub_count = len(acc["subs"])
            text += f"  u/{acc['username']} — <b>{acc['karma']:,}</b> → {sub_count} subs ({acc['va']})\n"

        await msg.delete()
        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"optimize error: {e}\n{traceback.format_exc()}")
        await msg.edit_text(f"Error: {e}")


# ── /heatmap — Engagement Heatmap ────────────────────────────────────────────

async def heatmap_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show which sub + time combos work best."""
    msg = await update.message.reply_text("Building engagement heatmap...", parse_mode=ParseMode.HTML)

    try:
        logs = get_table(TABLE_POSTING_LOGS).all()
        _ensure_va_cache()

        cutoff = now_utc() - timedelta(days=30)

        # Collect data: sub, hour, day-of-week
        sub_counts = Counter()
        sub_hours = defaultdict(Counter)  # sub -> hour -> count
        sub_days = defaultdict(Counter)   # sub -> day_name -> count
        va_subs = defaultdict(Counter)    # va -> sub -> count
        hourly_total = Counter()
        daily_total = Counter()
        total = 0

        day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

        for r in logs:
            d = parse_date_loose(safe_get(r, "Post Date"))
            url = safe_get(r, "Post URL", "")
            sub = _sub_from_url(url)
            if not d or d < cutoff or not sub:
                continue

            total += 1
            sub_counts[sub] += 1
            d_utc = d.astimezone(timezone.utc) if d.tzinfo else d
            sub_hours[sub][d_utc.hour] += 1
            sub_days[sub][day_names[d_utc.weekday()]] += 1
            hourly_total[d_utc.hour] += 1
            daily_total[day_names[d_utc.weekday()]] += 1

            va = _get_log_va_name(r)
            va_subs[va][sub] += 1

        if total == 0:
            return await msg.edit_text("No posts in the last 30 days.")

        text = (
            f"<b>🗺 Engagement Heatmap — 30 Days</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"Total posts: <b>{total}</b>\n\n"
        )

        # Hourly distribution (UTC)
        text += "<b>⏰ Posts by Hour (UTC)</b>\n"
        peak_hour = hourly_total.most_common(1)[0] if hourly_total else (0, 0)
        for hour in range(0, 24, 3):
            count = sum(hourly_total.get(h, 0) for h in range(hour, hour + 3))
            bar = "█" * min(count // max(total // 20, 1), 15)
            marker = " ← PEAK" if hour <= peak_hour[0] < hour + 3 else ""
            text += f"  {hour:02d}-{hour+2:02d}h: {bar} {count}{marker}\n"
        text += "\n"

        # Day of week
        text += "<b>📅 Posts by Day</b>\n"
        for day in day_names:
            count = daily_total.get(day, 0)
            bar = "█" * min(count // max(total // 30, 1), 10)
            text += f"  {day}: {bar} {count}\n"
        text += "\n"

        # Top subs
        text += f"<b>🔥 Top Subs ({len(sub_counts)} total)</b>\n"
        for sub, count in sub_counts.most_common(15):
            best_hour = sub_hours[sub].most_common(1)
            best_day = sub_days[sub].most_common(1)
            h_str = f"{best_hour[0][0]:02d}:00 UTC" if best_hour else "?"
            d_str = best_day[0][0] if best_day else "?"
            text += f"  r/{sub}: <b>{count}</b> posts (best: {d_str} @ {h_str})\n"
        text += "\n"

        # VA sub spread
        text += "<b>👥 VA Coverage</b>\n"
        for va, subs in sorted(va_subs.items(), key=lambda x: sum(x[1].values()), reverse=True):
            total_va = sum(subs.values())
            top_subs = ", ".join(f"r/{s}" for s, _ in subs.most_common(3))
            text += f"  {va}: {total_va} posts across {len(subs)} subs\n"
            text += f"    Top: {top_subs}\n"

        await msg.delete()
        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"heatmap error: {e}\n{traceback.format_exc()}")
        await msg.edit_text(f"Error: {e}")


# ── /deadsubs — Dead Sub Pruner ──────────────────────────────────────────────

async def deadsubs_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Find subs you're posting to that are dead or dying."""
    msg = await update.message.reply_text(
        "Scanning your subs for dead weight...\n"
        "<i>Checking activity levels for every sub in your logs</i>",
        parse_mode=ParseMode.HTML,
    )

    try:
        logs = get_table(TABLE_POSTING_LOGS).all()
        _ensure_va_cache()

        # Find all unique subs from recent logs
        cutoff = now_utc() - timedelta(days=30)
        sub_posts = Counter()
        for r in logs:
            d = parse_date_loose(safe_get(r, "Post Date"))
            url = safe_get(r, "Post URL", "")
            sub = _sub_from_url(url)
            if d and d > cutoff and sub:
                sub_posts[sub] += 1

        if not sub_posts:
            return await msg.edit_text("No subs found in recent logs.")

        unique_subs = list(sub_posts.keys())
        results = []

        for i, sub in enumerate(unique_subs):
            if i > 0 and i % 5 == 0:
                try:
                    await msg.edit_text(
                        f"Scanning subs... ({i}/{len(unique_subs)})",
                        parse_mode=ParseMode.HTML,
                    )
                except Exception:
                    pass

            await asyncio.sleep(2)
            info_data = await _reddit_get(f"https://www.reddit.com/r/{sub}/about.json")
            if not info_data:
                results.append({"sub": sub, "status": "unreachable", "subscribers": 0, "online": 0, "our_posts": sub_posts[sub]})
                continue

            info = info_data.get("data", {})
            if info_data.get("error") == 404 or info_data.get("reason") == "banned" or info_data.get("reason") == "private":
                results.append({"sub": sub, "status": "dead", "subscribers": 0, "online": 0, "our_posts": sub_posts[sub]})
                continue

            subs_count = info.get("subscribers", 0)
            online = info.get("accounts_active", 0)

            # Check how active — fetch newest post
            await asyncio.sleep(2)
            new_data = await _reddit_get(f"https://www.reddit.com/r/{sub}/new.json?limit=5")
            last_post_age = None
            posts_recent = 0
            if new_data:
                children = new_data.get("data", {}).get("children", [])
                if children:
                    newest_ts = children[0].get("data", {}).get("created_utc", 0)
                    if newest_ts:
                        last_post_age = (datetime.now(timezone.utc) - datetime.fromtimestamp(newest_ts, tz=timezone.utc)).total_seconds() / 3600
                    day_ago = datetime.now(timezone.utc).timestamp() - 86400
                    posts_recent = sum(1 for c in children if c.get("data", {}).get("created_utc", 0) > day_ago)

            # Classify
            if last_post_age is not None and last_post_age > 72:
                status = "dying"
            elif subs_count < 1000 and posts_recent == 0:
                status = "dead"
            elif online and subs_count and (online / subs_count) < 0.001:
                status = "low_engagement"
            else:
                status = "active"

            results.append({
                "sub": sub, "status": status, "subscribers": subs_count,
                "online": online, "our_posts": sub_posts[sub],
                "last_post_hours": round(last_post_age) if last_post_age else None,
                "nsfw": info.get("over18", False),
            })

        # Sort: dead/dying first
        status_order = {"dead": 0, "unreachable": 1, "dying": 2, "low_engagement": 3, "active": 4}
        results.sort(key=lambda x: status_order.get(x["status"], 99))

        dead = [r for r in results if r["status"] in ("dead", "unreachable")]
        dying = [r for r in results if r["status"] == "dying"]
        low = [r for r in results if r["status"] == "low_engagement"]
        healthy = [r for r in results if r["status"] == "active"]

        text = (
            f"<b>🧹 Dead Sub Pruner — {len(results)} subs</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n\n"
            f"✅ Active: <b>{len(healthy)}</b>  |  "
            f"📉 Dying: <b>{len(dying)}</b>  |  "
            f"💀 Dead: <b>{len(dead)}</b>  |  "
            f"😴 Low: <b>{len(low)}</b>\n\n"
        )

        if dead:
            text += "<b>💀 Dead / Unreachable — DROP THESE</b>\n"
            for r in dead:
                text += f"  r/{r['sub']} — you posted {r['our_posts']}x this month\n"
            text += "\n"

        if dying:
            text += "<b>📉 Dying — Last post 3+ days ago</b>\n"
            for r in dying:
                hrs = r.get("last_post_hours", "?")
                text += f"  r/{r['sub']} — {r['subscribers']:,} members, last post {hrs}h ago\n"
            text += "\n"

        if low:
            text += "<b>😴 Low Engagement</b>\n"
            for r in low:
                text += f"  r/{r['sub']} — {r['subscribers']:,} members, {r['online']} online\n"
            text += "\n"

        wasted_posts = sum(r["our_posts"] for r in dead + dying)
        if wasted_posts:
            text += f"<b>💡 You wasted ~{wasted_posts} posts on dead/dying subs this month</b>\n\n"

        text += f"<i>{len(healthy)} subs are healthy. Focus your effort there.</i>"

        await msg.delete()
        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"deadsubs error: {e}\n{traceback.format_exc()}")
        await msg.edit_text(f"Error: {e}")


# ── Mod Activity Scanner ──────────────────────────────────────────────────────

async def modscan_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Scan how active a subreddit's mod team is."""
    if not context.args:
        return await update.message.reply_text("Usage: /modscan <subreddit>")
    sub = context.args[0].strip().lower().removeprefix("r/")

    msg = await update.message.reply_text(
        f"🔍 Scanning mod team for r/{esc(sub)}...\n"
        f"<i>Pulling moderator list + activity</i>",
        parse_mode=ParseMode.HTML,
    )

    try:
        # ── 1. Fetch mod list ────────────────────────────────────────────
        mod_data = await _reddit_get(
            f"https://www.reddit.com/r/{sub}/about/moderators.json"
        )
        if not mod_data:
            return await msg.edit_text(
                f"❌ Couldn't fetch mod list for r/{esc(sub)}.\n"
                "Mod list may be hidden or the sub doesn't exist.",
                parse_mode=ParseMode.HTML,
            )

        raw_mods = (
            mod_data.get("data", {}).get("children", [])
            if isinstance(mod_data.get("data"), dict)
            else mod_data.get("data", [])
        )
        if not raw_mods:
            return await msg.edit_text(
                f"No moderators found for r/{esc(sub)} (list may be private).",
                parse_mode=ParseMode.HTML,
            )

        # ── 2. Fetch sub info for context ────────────────────────────────
        await asyncio.sleep(2)
        sub_info = await _reddit_get(f"https://www.reddit.com/r/{sub}/about.json")
        sub_members = 0
        sub_online = 0
        if sub_info:
            sd = sub_info.get("data", {})
            sub_members = sd.get("subscribers", 0)
            sub_online = sd.get("accounts_active", 0)

        # ── 3. Analyze each mod ──────────────────────────────────────────
        mods = []
        total = len(raw_mods)
        cap = min(total, 15)  # cap at 15 mods to avoid rate-limit hell

        for i, m in enumerate(raw_mods[:cap]):
            name = m.get("name", m.get("author", ""))
            if not name:
                continue
            perms = m.get("mod_permissions", [])
            added_utc = m.get("date", 0)

            if i > 0:
                await asyncio.sleep(2)
            if i > 0 and i % 5 == 0:
                try:
                    await msg.edit_text(
                        f"Scanning mods... ({i}/{cap})",
                        parse_mode=ParseMode.HTML,
                    )
                except Exception:
                    pass

            # Fetch mod's recent comments + posts
            profile = await _reddit_get(
                f"https://www.reddit.com/user/{name}/about.json"
            )
            await asyncio.sleep(2)
            comments = await _reddit_get(
                f"https://www.reddit.com/user/{name}/comments.json?limit=25&sort=new"
            )
            await asyncio.sleep(2)
            posts = await _reddit_get(
                f"https://www.reddit.com/user/{name}/submitted.json?limit=10&sort=new"
            )

            # Profile basics
            total_karma = 0
            account_age_days = 0
            if profile and profile.get("data"):
                pd_ = profile["data"]
                total_karma = pd_.get("total_karma", 0)
                created = pd_.get("created_utc", 0)
                if created:
                    account_age_days = int(
                        (datetime.now(timezone.utc) - datetime.fromtimestamp(created, tz=timezone.utc)).days
                    )

            # Last activity timestamp
            last_action_utc = 0
            activity_in_sub = 0  # actions in the target sub
            mod_actions_24h = 0

            day_ago = datetime.now(timezone.utc).timestamp() - 86400
            week_ago = datetime.now(timezone.utc).timestamp() - 604800

            comment_items = (
                comments.get("data", {}).get("children", []) if comments else []
            )
            post_items = (
                posts.get("data", {}).get("children", []) if posts else []
            )

            all_items = comment_items + post_items
            for item in all_items:
                d = item.get("data", {})
                ts = d.get("created_utc", 0)
                item_sub = (d.get("subreddit", "") or "").lower()
                if ts > last_action_utc:
                    last_action_utc = ts
                if item_sub == sub:
                    activity_in_sub += 1
                if ts > day_ago:
                    mod_actions_24h += 1

            # Calculate last active
            if last_action_utc:
                hours_ago = (datetime.now(timezone.utc).timestamp() - last_action_utc) / 3600
            else:
                hours_ago = None

            # Tenure as mod
            tenure_days = 0
            if added_utc:
                tenure_days = int(
                    (datetime.now(timezone.utc) - datetime.fromtimestamp(added_utc, tz=timezone.utc)).days
                )

            # Classify mod activity level
            if hours_ago is None or hours_ago > 720:  # 30+ days
                activity_level = "🔴 ghost"
            elif hours_ago > 168:  # 7+ days
                activity_level = "🟡 slow"
            elif hours_ago > 24:
                activity_level = "🟢 active"
            else:
                activity_level = "⚡ very active"

            mods.append({
                "name": name,
                "perms": perms,
                "tenure_days": tenure_days,
                "total_karma": total_karma,
                "account_age_days": account_age_days,
                "hours_ago": hours_ago,
                "activity_in_sub": activity_in_sub,
                "actions_24h": mod_actions_24h,
                "activity_level": activity_level,
                "is_bot": name.lower().endswith("bot") or name.lower().startswith("bot"),
            })

        # ── 4. Build report ──────────────────────────────────────────────
        ghosts = [m for m in mods if "ghost" in m["activity_level"]]
        slow = [m for m in mods if "slow" in m["activity_level"]]
        active = [m for m in mods if "active" in m["activity_level"] and "very" not in m["activity_level"]]
        very_active = [m for m in mods if "very active" in m["activity_level"]]
        bots = [m for m in mods if m["is_bot"]]

        # Threat level
        if len(very_active) >= 3:
            threat = "🔴 HIGH — multiple hyperactive mods"
        elif len(very_active) >= 1 and len(active) >= 2:
            threat = "🟠 MEDIUM-HIGH — active mod presence"
        elif len(active) >= 1:
            threat = "🟡 MEDIUM — some active mods"
        elif len(slow) >= 1:
            threat = "🟢 LOW — mods are slow/inactive"
        else:
            threat = "✅ MINIMAL — ghost mod team"

        text = (
            f"<b>🛡️ Mod Scan — r/{esc(sub)}</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
        )
        if sub_members:
            text += f"👥 {sub_members:,} members | {sub_online:,} online\n"
        text += (
            f"👮 {total} total mods (scanned {cap})\n"
            f"🤖 Bots: {len(bots)}\n\n"
            f"<b>⚠️ Threat Level: {threat}</b>\n\n"
        )

        # Breakdown
        text += (
            f"⚡ Very Active (24h): <b>{len(very_active)}</b>\n"
            f"🟢 Active (1-7d): <b>{len(active)}</b>\n"
            f"🟡 Slow (7-30d): <b>{len(slow)}</b>\n"
            f"🔴 Ghost (30d+): <b>{len(ghosts)}</b>\n\n"
        )

        # Individual mod details
        text += "<b>👮 Mod Breakdown:</b>\n"
        for m in mods:
            if m["is_bot"]:
                tag = "🤖"
            else:
                tag = m["activity_level"].split(" ")[0]

            # Format last active
            if m["hours_ago"] is None:
                last_str = "unknown"
            elif m["hours_ago"] < 1:
                last_str = "< 1h ago"
            elif m["hours_ago"] < 24:
                last_str = f"{int(m['hours_ago'])}h ago"
            elif m["hours_ago"] < 720:
                last_str = f"{int(m['hours_ago'] / 24)}d ago"
            else:
                last_str = f"{int(m['hours_ago'] / 720)}mo+ ago"

            perms_str = ""
            if m["perms"]:
                if "all" in m["perms"]:
                    perms_str = " [full perms]"
                else:
                    perms_str = f" [{', '.join(m['perms'][:3])}]"

            sub_activity = ""
            if m["activity_in_sub"] > 0:
                sub_activity = f" | {m['activity_in_sub']} actions in sub"

            text += (
                f"  {tag} u/{esc(m['name'])} — last active: {last_str}"
                f"{sub_activity}{perms_str}\n"
            )

        text += "\n"

        # Tactical summary
        text += "<b>📋 Tactical Summary:</b>\n"
        if len(ghosts) > len(mods) / 2:
            text += "• Most mods are ghosts — low enforcement risk\n"
        if len(very_active) == 0:
            text += "• No hyperactive mods — posts unlikely to be caught fast\n"
        if len(very_active) >= 2:
            text += "• Multiple very active mods — expect fast enforcement\n"
        real_mods = [m for m in mods if not m["is_bot"]]
        sub_present = [m for m in real_mods if m["activity_in_sub"] >= 3]
        if sub_present:
            names = ", ".join(f"u/{m['name']}" for m in sub_present[:3])
            text += f"• Watch out for: {names} (active in this sub)\n"
        if bots:
            bot_names = ", ".join(f"u/{m['name']}" for m in bots[:3])
            text += f"• Automod bots detected: {bot_names}\n"
        if not sub_present and not very_active:
            text += "• ✅ Safe to operate — low mod presence\n"

        # Skipped mods note
        if total > cap:
            text += f"\n<i>⚠️ Only scanned top {cap} of {total} mods (rate limit)</i>"

        await msg.delete()
        await reply(update, text, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"modscan error: {e}\n{traceback.format_exc()}")
        await msg.edit_text(f"Error: {e}")


# ── Scraper commands (merged from scraper bot) ───────────────────────────────

async def sub_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await reply(update, "Usage: <code>/sub subreddit_name</code>", parse_mode=ParseMode.HTML)
    sub = context.args[0].strip().lstrip("r/").lstrip("/")
    msg = await update.message.reply_text(f"Fetching r/{sub}...")
    info = await reddit.fetch_subreddit_info(sub)
    if not info or (isinstance(info, dict) and info.get("_error")):
        return await msg.edit_text(f"Could not find r/{sub}. Check the name and try again.")
    posts = await reddit.fetch_posts(sub, sort="hot", limit=10)
    reqs = await reddit.detect_requirements(sub)
    nsfw_tag = " [NSFW]" if info["nsfw"] else ""
    text = (
        f"<b>r/{esc(info['name'])}</b> — {reddit._fmt_number(info['subscribers'])} members{nsfw_tag}\n"
        f"━━━━━━━━━━━━━━━━━━\n\n"
    )
    online = reddit._fmt_number(info["active_users"]) if info["active_users"] else "?"
    age = reddit._age_str(info["created_utc"])
    text += (
        f"Online: {online}  |  Age: {age}\n"
        f"Images: {'Yes' if info['allow_images'] else 'No'}  |  "
        f"Videos: {'Yes' if info['allow_videos'] else 'No'}\n\n"
    )
    desc = info.get("description", "").strip()
    if desc:
        text += f"<i>{esc(desc[:200])}</i>\n\n"
    if posts:
        avg_score = sum(p["score"] for p in posts) // len(posts)
        avg_comments = sum(p["comments"] for p in posts) // len(posts)
        text += (
            f"<b>Avg Engagement (hot):</b>  {reddit._fmt_number(avg_score)} upvotes  |  "
            f"{reddit._fmt_number(avg_comments)} comments\n\n"
        )
        text += "<b>Hot Posts</b>\n"
        for i, p in enumerate(posts[:5], 1):
            title = esc(p["title"][:60])
            if len(p["title"]) > 60:
                title += "..."
            text += (
                f"  {i}. {title}\n"
                f"     {reddit._fmt_number(p['score'])} upvotes  |  "
                f"{p['comments']} comments  |  {reddit._time_ago(p['created_utc'])}\n\n"
            )
    text += "<b>Detected Requirements</b>\n"
    if reqs["min_karma"]:
        text += f"  Karma: min {reqs['min_karma']}\n"
    elif reqs["min_comment_karma"] or reqs["min_post_karma"]:
        if reqs["min_comment_karma"]:
            text += f"  Comment Karma: min {reqs['min_comment_karma']}\n"
        if reqs["min_post_karma"]:
            text += f"  Post Karma: min {reqs['min_post_karma']}\n"
    else:
        text += "  Karma: not detected\n"
    if reqs["min_age_days"]:
        text += f"  Account Age: min {reqs['min_age_days']} days\n"
    else:
        text += "  Account Age: not detected\n"
    if reqs["verification"]:
        text += "  Verification: required\n"
    if reqs["flair_required"]:
        text += "  Flair: required\n"
    text += f"\n<i>Use /reqs {sub} for full requirements breakdown</i>"
    await msg.edit_text(text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)


async def reqs_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await reply(update, "Usage: <code>/reqs subreddit_name</code>", parse_mode=ParseMode.HTML)
    sub = context.args[0].strip().lstrip("r/").lstrip("/")
    msg = await update.message.reply_text(
        f"Analyzing r/{sub}...\n"
        f"<i>Scanning posts and profiling users — this takes a moment</i>",
        parse_mode=ParseMode.HTML,
    )
    floor_task = asyncio.create_task(reddit.analyze_sub_floor(sub, hours_back=3, max_posts=50))
    reqs_task = asyncio.create_task(reddit.detect_requirements(sub))
    floor = await floor_task
    reqs = await reqs_task
    if not floor:
        return await msg.edit_text(f"Could not analyze r/{sub}. Check the name.")
    nsfw_tag = " [NSFW]" if floor.get("nsfw") else ""
    level = floor.get("activity_level", "?")
    level_emoji = {"VERY ACTIVE": "\U0001f525", "ACTIVE": "\U0001f4c8", "MODERATE": "\U0001f4ca", "LOW": "\U0001f4a4"}.get(level, "")
    text = (
        f"<b>Analysis for r/{esc(sub)}</b>{nsfw_tag}\n"
        f"━━━━━━━━━━━━━━━━━━\n\n"
        f"<b>Activity:</b>  {level_emoji} {level}\n"
        f"<b>Subscribers:</b>  {floor['subscribers']:,}\n"
    )
    if floor.get("sub_age_days"):
        text += f"<b>Subreddit age:</b>  {floor['sub_age_days']} days\n"
    text += f"<b>Activity:</b>  ~{floor['posts_per_day']} posts/day\n\n"
    lk = floor.get("lowest_karma")
    if lk:
        lk_link = f"  <a href=\"{lk['post_url']}\">View post</a>\n" if lk.get("post_url") else ""
        text += (
            f"<b>\U0001f447 Lowest Karma Account</b>\n"
            f"  Total karma: <b>{lk['total_karma']:,}</b>\n"
            f"  Post karma: {lk['post_karma']:,}\n"
            f"  Comment karma: {lk['comment_karma']:,}\n"
            f"  User: u/{esc(lk['username'])}\n"
            f"  Account age: {lk['age']} (created {lk['created_date']})\n"
            f"  Post: <i>{esc(lk['post_title'])}</i>\n"
            f"{lk_link}\n"
        )
    na = floor.get("newest_account")
    if na and (not lk or na["username"] != lk["username"]):
        na_link = f"  <a href=\"{na['post_url']}\">View post</a>\n" if na.get("post_url") else ""
        text += (
            f"<b>\U0001f476 Newest Account</b>\n"
            f"  Total karma: <b>{na['total_karma']:,}</b>\n"
            f"  Post karma: {na['post_karma']:,}\n"
            f"  Comment karma: {na['comment_karma']:,}\n"
            f"  User: u/{esc(na['username'])}\n"
            f"  Account age: {na['age']} (created {na['created_date']})\n"
            f"  Post: <i>{esc(na['post_title'])}</i>\n"
            f"{na_link}\n"
        )
    has_rule_reqs = (
        reqs.get("min_karma") or reqs.get("min_comment_karma") or
        reqs.get("min_post_karma") or reqs.get("min_age_days") or
        reqs.get("verification") or reqs.get("flair_required")
    )
    if has_rule_reqs:
        text += "<b>From Rules/Sidebar</b>\n"
        if reqs["min_karma"]:
            text += f"  Karma requirement: {reqs['min_karma']}\n"
        if reqs["min_comment_karma"]:
            text += f"  Comment karma: {reqs['min_comment_karma']}\n"
        if reqs["min_post_karma"]:
            text += f"  Post karma: {reqs['min_post_karma']}\n"
        if reqs["min_age_days"]:
            text += f"  Account age: {reqs['min_age_days']} days\n"
        if reqs["verification"]:
            text += f"  Verification: required\n"
        if reqs["flair_required"]:
            text += f"  Flair: required\n"
        if reqs["posting_frequency"]:
            text += f"  Frequency: {esc(reqs['posting_frequency'])}\n"
        text += "\n"
    if reqs.get("key_rules"):
        text += f"<b>Rules ({reqs['raw_rules_count']})</b>\n"
        for r in reqs["key_rules"][:10]:
            text += f"  • {esc(r[:70])}\n"
        if len(reqs["key_rules"]) > 10:
            text += f"  <i>...and {len(reqs['key_rules']) - 10} more</i>\n"
        text += "\n"
    text += f"<i>Based on posts older than {floor['hours_back']} hours. {floor['users_checked']} users checked.</i>"
    await msg.edit_text(text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)


async def profile_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await reply(update, "Usage: <code>/profile username</code>", parse_mode=ParseMode.HTML)
    username = context.args[0].strip().lstrip("u/").lstrip("/")
    msg = await update.message.reply_text(f"Profiling u/{username}...")
    profile = await reddit.fetch_user_profile(username)
    if not profile:
        return await msg.edit_text("Could not reach Reddit. Try again later.")
    if profile.get("suspended"):
        return await msg.edit_text(
            f"<b>u/{esc(username)} — SUSPENDED / BANNED</b>\n\n"
            f"Reddit returns 403/404 for this account.",
            parse_mode=ParseMode.HTML,
        )
    posts = await reddit.fetch_user_posts(username, limit=100)
    comments = await reddit.fetch_user_comments(username, limit=100)
    text = (
        f"<b>u/{esc(profile['username'])}</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n\n"
        f"<b>Karma:</b>  {profile['total_karma']:,}  "
        f"(Post: {profile['post_karma']:,}  |  Comment: {profile['comment_karma']:,})\n"
        f"<b>Age:</b>  {profile['age']}  |  Created: {profile['created_date']}\n"
    )
    if profile.get("nsfw"):
        text += "<b>NSFW Profile:</b>  Yes\n"
    text += "\n"
    if posts:
        sub_counts = Counter(p["subreddit"] for p in posts)
        text += f"<b>Post Activity</b>  ({len(posts)} recent posts)\n"
        for sub_name, count in sub_counts.most_common(8):
            text += f"  r/{esc(sub_name)} — {count} posts\n"
        if len(sub_counts) > 8:
            text += f"  <i>...and {len(sub_counts) - 8} more subs</i>\n"
        text += "\n"
        top = sorted(posts, key=lambda x: x["score"], reverse=True)[:5]
        if top and top[0]["score"] > 0:
            text += "<b>Top Posts</b>\n"
            for p in top:
                title = esc(p["title"][:50])
                if len(p["title"]) > 50:
                    title += "..."
                text += (
                    f"  {reddit._fmt_number(p['score'])} upvotes — {title}\n"
                    f"  r/{esc(p['subreddit'])}  |  {reddit._time_ago(p['created_utc'])}\n\n"
                )
    if comments:
        csub_counts = Counter(c["subreddit"] for c in comments)
        text += f"<b>Comment Activity</b>  ({len(comments)} recent)\n"
        for sub_name, count in csub_counts.most_common(5):
            text += f"  r/{esc(sub_name)} — {count} comments\n"
        text += "\n"
    text += f"https://old.reddit.com/user/{username}"
    await msg.edit_text(text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)


async def similar_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await reply(update, "Usage: <code>/similar subreddit_name</code>", parse_mode=ParseMode.HTML)
    sub = context.args[0].strip().lstrip("r/").lstrip("/")
    msg = await update.message.reply_text(
        f"Finding subs similar to r/{sub}...\n"
        f"<i>Sampling users and checking post history — this takes ~60s</i>",
        parse_mode=ParseMode.HTML,
    )
    results = await reddit.find_similar_subs(sub, sample_size=25)
    if not results:
        return await msg.edit_text(
            f"Could not find similar subs for r/{sub}. "
            f"The sub might be too small or private."
        )
    info = await reddit.fetch_subreddit_info(sub)
    nsfw_tag = ""
    if info and not isinstance(info, dict) or (isinstance(info, dict) and not info.get("_error")):
        if info and info.get("nsfw"):
            nsfw_tag = " [NSFW]"
    text = (
        f"<b>Subs Similar to r/{esc(sub)}</b>{nsfw_tag}\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"<i>Based on user overlap (25 users sampled)</i>\n\n"
    )
    for i, r in enumerate(results, 1):
        nsfw_flag = " [NSFW]" if r["nsfw"] else ""
        subs = reddit._fmt_number(r["subscribers"]) if r["subscribers"] else "?"
        text += (
            f"  <b>{i}.</b>  r/{esc(r['name'])} — {r['overlap_pct']}% overlap\n"
            f"       {subs} members{nsfw_flag}\n\n"
        )
    text += f"<i>Use /reqs &lt;sub&gt; to check posting requirements</i>"
    await msg.edit_text(text, parse_mode=ParseMode.HTML)


async def nsfw_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await reply(update, "Usage: <code>/nsfw search_term</code>", parse_mode=ParseMode.HTML)
    query = " ".join(context.args).strip()
    msg = await update.message.reply_text(f"Searching NSFW subs for \"{esc(query)}\"...", parse_mode=ParseMode.HTML)
    results = await reddit.search_subreddits(query, nsfw=True, limit=20)
    nsfw_results = [r for r in results if r["nsfw"]]
    if not nsfw_results:
        return await msg.edit_text(
            f"No NSFW subs found for \"{esc(query)}\".\nTry different keywords.",
            parse_mode=ParseMode.HTML,
        )
    text = (
        f"<b>NSFW Subs — \"{esc(query)}\"</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n\n"
    )
    for i, r in enumerate(nsfw_results[:15], 1):
        subs = reddit._fmt_number(r["subscribers"])
        online = reddit._fmt_number(r["active"]) if r["active"] else "?"
        desc = esc(r["description"][:80]) if r["description"] else ""
        text += (
            f"  <b>{i}.</b>  r/{esc(r['name'])} — {subs} members\n"
            f"       Online: {online}"
        )
        if desc:
            text += f"\n       <i>{desc}</i>"
        text += "\n\n"
    text += f"<i>Use /reqs &lt;sub&gt; for posting requirements</i>"
    await msg.edit_text(text, parse_mode=ParseMode.HTML)


async def hot_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await reply(update, "Usage: <code>/hot subreddit [count]</code>", parse_mode=ParseMode.HTML)
    sub = context.args[0].strip().lstrip("r/").lstrip("/")
    count = 10
    if len(context.args) > 1:
        try:
            count = min(int(context.args[1]), 25)
        except ValueError:
            pass
    msg = await update.message.reply_text(f"Fetching hot posts from r/{sub}...")
    posts = await reddit.fetch_posts(sub, sort="hot", limit=count)
    if not posts:
        return await msg.edit_text(f"Could not fetch posts from r/{sub}. Check the name.")
    text = (
        f"<b>r/{esc(sub)} — Hot Right Now</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n\n"
    )
    for i, p in enumerate(posts[:count], 1):
        title = esc(p["title"][:70])
        if len(p["title"]) > 70:
            title += "..."
        flair = f" [{esc(p['flair'])}]" if p.get("flair") else ""
        text += (
            f"<b>{i}.</b>  {title}{flair}\n"
            f"    {reddit._fmt_number(p['score'])} upvotes  |  "
            f"{p['comments']} comments  |  "
            f"{reddit._time_ago(p['created_utc'])}  |  "
            f"u/{esc(p['author'])}\n\n"
        )
    await msg.edit_text(text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)


_bulk_waiting = set()


async def bulk_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start a bulk analysis. Accepts subs inline or waits for a list."""
    chat_id = update.effective_chat.id
    raw = update.message.text or ""
    raw = raw.split(None, 1)[1] if len(raw.split(None, 1)) > 1 else ""
    if not raw.strip():
        _bulk_waiting.add(chat_id)
        return await reply(
            update,
            "Send me a list of subreddits to analyze.\n"
            "<i>One per line, comma-separated, or space-separated.</i>",
            parse_mode=ParseMode.HTML,
        )
    await _run_bulk(update, raw)


async def bulk_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Catch the subreddit list after /bulk was sent without args."""
    chat_id = update.effective_chat.id
    if chat_id not in _bulk_waiting:
        return
    _bulk_waiting.discard(chat_id)
    await _run_bulk(update, update.message.text)


async def _run_bulk(update: Update, raw_text: str):
    """Parse the sub list and analyze each one."""
    raw_text = raw_text.replace(",", "\n").replace(" ", "\n")
    subs = []
    for line in raw_text.split("\n"):
        s = line.strip().lstrip("r/").lstrip("/").strip()
        if s and s not in subs:
            subs.append(s)
    if not subs:
        return await reply(update, "No subreddits found. Send names separated by commas or newlines.")
    if len(subs) > 50:
        return await reply(update, f"Too many subs ({len(subs)}). Max 50 at a time.")
    msg = await update.message.reply_text(
        f"Analyzing <b>{len(subs)}</b> subreddits...\n"
        f"<i>This will take a while — scanning posts and profiling users</i>",
        parse_mode=ParseMode.HTML,
    )
    results = []
    failed = []
    for i, sub in enumerate(subs):
        if i > 0 and i % 5 == 0:
            try:
                await msg.edit_text(
                    f"Analyzing <b>{len(subs)}</b> subreddits... ({i}/{len(subs)})\n"
                    f"<i>Currently: r/{esc(sub)}</i>",
                    parse_mode=ParseMode.HTML,
                )
            except Exception:
                pass
        try:
            floor = await reddit.analyze_sub_floor(sub, hours_back=6, max_posts=30)
            if floor and floor.get("users_checked", 0) > 0:
                results.append((sub, floor))
            else:
                failed.append(sub)
        except Exception as e:
            logger.error(f"Bulk analysis failed for r/{sub}: {e}")
            failed.append(sub)
    if not results:
        return await msg.edit_text("Could not analyze any of those subreddits. Check the names.")
    text = (
        f"<b>Bulk Analysis — {len(results)} subreddits</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n\n"
    )
    for sub, floor in results:
        nsfw_tag = " [NSFW]" if floor.get("nsfw") else ""
        subs_fmt = reddit._fmt_number(floor["subscribers"])
        text += f"<b>r/{esc(sub)}</b> — {subs_fmt} members{nsfw_tag}\n"
        lk = floor.get("lowest_karma")
        if lk:
            lk_link = f"<a href=\"{lk['post_url']}\">post</a>" if lk.get("post_url") else ""
            text += (
                f"  \U0001f447 Lowest karma: <b>{lk['total_karma']:,}</b> "
                f"(u/{esc(lk['username'])} — {lk['age']})"
            )
            if lk_link:
                text += f"  {lk_link}"
            text += "\n"
        else:
            text += "  \U0001f447 Lowest karma: no data\n"
        na = floor.get("newest_account")
        if na:
            na_link = f"<a href=\"{na['post_url']}\">post</a>" if na.get("post_url") else ""
            text += (
                f"  \U0001f476 Newest account: <b>{na['age']}</b> "
                f"(u/{esc(na['username'])} — {na['total_karma']:,} karma)"
            )
            if na_link:
                text += f"  {na_link}"
            text += "\n"
        else:
            text += "  \U0001f476 Newest account: no data\n"
        text += f"  Activity: ~{floor['posts_per_day']} posts/day\n\n"
    if failed:
        text += f"<i>Failed: {', '.join(failed)}</i>\n\n"
    text += f"<i>{len(results)} subs analyzed. Use /reqs &lt;sub&gt; for details.</i>"
    await msg.delete()
    await reply(update, text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)


# ── Error handler ─────────────────────────────────────────────────────────────

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Exception: {context.error}", exc_info=context.error)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if not BOT_TOKEN:
        print("Set BOT_TOKEN environment variable!")
        return
    if not AIRTABLE_TOKEN:
        print("Set AIRTABLE_TOKEN environment variable!")
        return

    app = Application.builder().token(BOT_TOKEN).build()

    # Pipeline commands
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("help", start_cmd))
    app.add_handler(CommandHandler("status", status_cmd))
    app.add_handler(CommandHandler("blanks", blanks_cmd))
    app.add_handler(CommandHandler("warmup", warmup_cmd))
    app.add_handler(CommandHandler("posting", posting_cmd))
    app.add_handler(CommandHandler("logs", logs_cmd))
    app.add_handler(CommandHandler("bans", bans_cmd))
    app.add_handler(CommandHandler("accounts", accounts_cmd))
    app.add_handler(CommandHandler("daily", daily_cmd))
    app.add_handler(CommandHandler("needaccs", needaccs_cmd))

    # VA commands
    app.add_handler(CommandHandler("mystats", mystats_cmd))
    app.add_handler(CommandHandler("vastats", vastats_cmd))

    # Account tools
    app.add_handler(CommandHandler("refresh", refresh_cmd))
    app.add_handler(CommandHandler("checkbans", checkbans_cmd))
    app.add_handler(CommandHandler("postcheck", postcheck_cmd))
    app.add_handler(CommandHandler("reassign", assign_acc_cmd))
    app.add_handler(CommandHandler("topaccs", topaccs_cmd))
    app.add_handler(CommandHandler("warnings", warnings_cmd))

    # Config commands
    app.add_handler(CommandHandler("settopic", settopic_cmd))
    app.add_handler(CommandHandler("unsettopic", unsettopic_cmd))
    app.add_handler(CommandHandler("topics", topics_cmd))
    app.add_handler(CommandHandler("setbanchannel", setbanchannel_cmd))
    app.add_handler(CommandHandler("setreportchannel", setreportchannel_cmd))
    app.add_handler(CommandHandler("linkva", linkva_cmd))

    # Role commands (preserved)
    app.add_handler(CommandHandler("createrole", createrole))
    app.add_handler(CommandHandler("deleterole", deleterole))
    app.add_handler(CommandHandler("assign", assign))
    app.add_handler(CommandHandler("unassign", unassign))
    app.add_handler(CommandHandler("roles", roles_cmd))
    app.add_handler(CommandHandler("myroles", myroles))
    app.add_handler(CommandHandler("tag", tag))

    # Analytics / intel commands
    app.add_handler(CommandHandler("postaudit", postaudit_cmd))
    app.add_handler(CommandHandler("plan", plan_cmd))
    app.add_handler(CommandHandler("optimize", optimize_cmd))
    app.add_handler(CommandHandler("heatmap", heatmap_cmd))
    app.add_handler(CommandHandler("deadsubs", deadsubs_cmd))
    app.add_handler(CommandHandler("modscan", modscan_cmd))

    # Scraper commands
    app.add_handler(CommandHandler("sub", sub_cmd))
    app.add_handler(CommandHandler("reqs", reqs_cmd))
    app.add_handler(CommandHandler("profile", profile_cmd))
    app.add_handler(CommandHandler("similar", similar_cmd))
    app.add_handler(CommandHandler("nsfw", nsfw_cmd))
    app.add_handler(CommandHandler("hot", hot_cmd))
    app.add_handler(CommandHandler("bulk", bulk_cmd))

    # Text handler — auto link detection + bulk sub list follow-up
    async def combined_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
        chat_id = update.effective_chat.id
        if chat_id in _bulk_waiting:
            await bulk_text_handler(update, context)
            return
        await handle_message(update, context)

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, combined_text_handler))

    # Error handler
    app.add_error_handler(error_handler)

    # Schedule ban polling & weekly leaderboard
    job_queue = app.job_queue
    if job_queue:
        job_queue.run_repeating(poll_bans, interval=BAN_POLL_INTERVAL, first=30)
        job_queue.run_repeating(flush_post_logs, interval=POST_LOG_FLUSH_INTERVAL, first=POST_LOG_FLUSH_INTERVAL)
        job_queue.run_repeating(
            update_account_info_job,
            interval=ACCOUNT_UPDATE_INTERVAL,
            first=120,  # first run 2 min after startup
        )
        # Activity reports at 10 AM and 6 PM IST daily
        job_queue.run_daily(
            post_activity_report,
            time=datetime.strptime("04:30", "%H:%M").time(),  # 10:00 AM IST = 04:30 UTC
        )
        job_queue.run_daily(
            post_activity_report,
            time=datetime.strptime("12:30", "%H:%M").time(),  # 6:00 PM IST = 12:30 UTC
        )
        job_queue.run_daily(
            weekly_leaderboard,
            time=datetime.strptime("09:00", "%H:%M").time(),
            days=(0,),  # Monday
        )
        logger.info("Job queue active: ban polling + account updates + weekly leaderboard scheduled")
    else:
        logger.warning("No JobQueue available — install python-telegram-bot[job-queue] for ban polling & leaderboard")

    # Register command menu in Telegram
    async def post_init(application):
        await application.bot.set_my_commands([
            # --- Pipeline & Reports ---
            ("status", "Full pipeline overview"),
            ("daily", "Complete daily report"),
            ("blanks", "Blank accounts report"),
            ("warmup", "Warmup progress"),
            ("posting", "Posting accounts"),
            ("bans", "Banned accounts"),
            ("logs", "Posting logs"),
            ("accounts", "Per-model breakdown"),
            ("needaccs", "VAs low on accounts"),
            # --- Account Tools ---
            ("refresh", "Update karma/age from Reddit"),
            ("checkbans", "Scan all stages for bans"),
            ("postcheck", "Shadowban checker"),
            ("topaccs", "Highest karma accounts"),
            ("warnings", "Accounts needing attention"),
            # --- Analytics ---
            ("postaudit", "Check if posts got removed"),
            ("heatmap", "Engagement heatmap"),
            ("optimize", "Portfolio optimizer"),
            ("deadsubs", "Find dead subreddits"),
            # --- Reddit Intel ---
            ("sub", "Subreddit intel"),
            ("reqs", "Sub posting requirements"),
            ("hot", "Hot posts in a sub"),
            ("profile", "Reddit user profile"),
            ("similar", "Find similar subs"),
            ("nsfw", "Search NSFW subs"),
            ("bulk", "Analyze multiple subs"),
            ("modscan", "Scan mod activity"),
            ("plan", "Sub infiltration plan"),
            # --- VA Stats ---
            ("mystats", "Your personal stats"),
            ("vastats", "VA dashboard (admin)"),
            # --- Roles ---
            ("createrole", "Create a role"),
            ("assign", "Assign role to users"),
            ("unassign", "Remove role from user"),
            ("roles", "List all roles"),
            ("tag", "Ping role members"),
            ("help", "All commands"),
        ])

    app.post_init = post_init

    logger.info("Reddit Operations Bot starting...")
    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()
