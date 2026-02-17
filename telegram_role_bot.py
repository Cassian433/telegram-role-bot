import json
import os
import logging
import traceback
import re
from typing import Dict, Any, List, Tuple, Optional

from telegram import Update, MessageEntity
from telegram.ext import Application, CommandHandler, ContextTypes

# Put your token in an env var named TELEGRAM_BOT_TOKEN
# Windows PowerShell:   setx TELEGRAM_BOT_TOKEN "123:ABC"
# Linux/macOS:          export TELEGRAM_BOT_TOKEN="123:ABC"
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()

DATA_FILE = os.path.join(os.path.dirname(__file__), "roles_data.json")

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("rolebot")

# -------------------------
# Helpers
# -------------------------
def html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def norm_role(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s

def load_data() -> Dict[str, Any]:
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_data(data: Dict[str, Any]) -> None:
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def ensure_chat(data: Dict[str, Any], chat_id: str) -> Dict[str, Any]:
    """
    schema:
      data[chat_id] = {
        "roles": { role_name: true },
        "assignments": { user_id_str: [role_name, ...] },
        "users": { user_id_str: { "name": "First", "username": "foo" } }
      }
    """
    if chat_id not in data:
        data[chat_id] = {"roles": {}, "assignments": {}, "users": {}}
    if "users" not in data[chat_id]:
        data[chat_id]["users"] = {}
    return data[chat_id]

async def safe_send(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str, html: bool = False) -> None:
    chat_id = update.effective_chat.id
    thread_id = getattr(update.effective_message, "message_thread_id", None)

    try:
        await context.bot.send_message(
            chat_id=chat_id,
            text=text,
            parse_mode="HTML" if html else None,
            message_thread_id=thread_id,
            disable_web_page_preview=True
        )
    except Exception as e:
        logger.error(f"send_message failed: {e}")
        # last-ditch attempt without thread_id
        try:
            await context.bot.send_message(
                chat_id=chat_id,
                text=text,
                parse_mode="HTML" if html else None,
                disable_web_page_preview=True
            )
        except Exception as e2:
            logger.error(f"send_message fallback failed: {e2}")

async def check_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if update.effective_chat.type == "private":
        return True
    try:
        member = await context.bot.get_chat_member(update.effective_chat.id, update.effective_user.id)
        return member.status in ("administrator", "creator")
    except Exception as e:
        logger.error(f"Admin check failed: {e}")
        return False

def upsert_user(chat: Dict[str, Any], user_id: int, name: str, username: Optional[str]) -> None:
    uid = str(user_id)
    chat["users"][uid] = {"name": name or "User", "username": (username or "").lstrip("@")}

def parse_role_and_targets(update: Update) -> Tuple[Optional[str], List[Tuple[int, str]]]:
    """
    Targets supported:
      - Reply target
      - text_mention entities (click mentions)
      - Numeric IDs typed after role

    Role can be multi-word: it is the text after the command up to the first target (entity or numeric id).
    """
    msg = update.effective_message
    if not msg or not msg.text:
        return None, []

    text = msg.text
    entities = msg.entities or []

    targets: List[Tuple[int, str]] = []

    # Reply target
    if msg.reply_to_message and msg.reply_to_message.from_user:
        u = msg.reply_to_message.from_user
        targets.append((u.id, u.first_name or "User"))

    # Click mentions
    for ent in entities:
        if ent.type == MessageEntity.TEXT_MENTION and ent.user:
            targets.append((ent.user.id, ent.user.first_name or "User"))

    # Numeric IDs in args
    parts = text.split()
    if len(parts) > 1:
        for tok in parts[1:]:
            if tok.isdigit():
                targets.append((int(tok), f"ID {tok}"))

    # Dedup
    seen = {}
    for uid, label in targets:
        seen[uid] = label
    targets = [(uid, seen[uid]) for uid in seen]

    # Role parsing
    # find args start
    first_space = text.find(" ")
    if first_space == -1:
        return None, targets
    args_start = first_space + 1

    role_end = None

    # earliest text_mention entity offset
    mention_offsets = [ent.offset for ent in entities if ent.type == MessageEntity.TEXT_MENTION]
    if mention_offsets:
        role_end = min(mention_offsets)

    # earliest numeric token offset (>=4 digits to reduce false positives)
    segment = text[args_start:]
    m = re.search(r"\b\d{4,}\b", segment)
    if m:
        num_off = args_start + m.start()
        role_end = num_off if role_end is None else min(role_end, num_off)

    role_raw = text[args_start:].strip() if role_end is None else text[args_start:role_end].strip()
    role = norm_role(role_raw)
    if not role:
        return None, targets

    return role, targets

# -------------------------
# Commands
# -------------------------
async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Exception: {context.error}")
    logger.error(traceback.format_exc())

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await safe_send(
        update, context,
        "Role Bot\n\n"
        "Admin:\n"
        "  /createrole <name>\n"
        "  /deleterole <name>\n"
        "  /assign <role name...> (reply / click-mention / IDs)\n"
        "  /unassign <role name...> (reply / click-mention / IDs)\n\n"
        "Everyone:\n"
        "  /roles\n"
        "  /myroles\n"
        "  /tag <role name...>\n",
        html=False
    )

async def createrole(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_admin(update, context):
        return await safe_send(update, context, "Only admins can create roles.")

    if not context.args:
        return await safe_send(update, context, "Usage: /createrole <name>")

    role = norm_role(" ".join(context.args))
    data = load_data()
    chat = ensure_chat(data, str(update.effective_chat.id))

    if role in chat["roles"]:
        return await safe_send(update, context, f"Role '{role}' already exists.")

    chat["roles"][role] = True
    save_data(data)
    await safe_send(update, context, f"Role '{role}' created.")

async def deleterole(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_admin(update, context):
        return await safe_send(update, context, "Only admins can delete roles.")

    if not context.args:
        return await safe_send(update, context, "Usage: /deleterole <name>")

    role = norm_role(" ".join(context.args))
    data = load_data()
    chat = ensure_chat(data, str(update.effective_chat.id))

    if role not in chat["roles"]:
        return await safe_send(update, context, f"Role '{role}' doesn't exist.")

    del chat["roles"][role]
    for uid in list(chat["assignments"].keys()):
        if role in chat["assignments"][uid]:
            chat["assignments"][uid].remove(role)
            if not chat["assignments"][uid]:
                del chat["assignments"][uid]

    save_data(data)
    await safe_send(update, context, f"Role '{role}' deleted.")

async def assign(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_admin(update, context):
        return await safe_send(update, context, "Only admins can assign roles.")

    role, targets = parse_role_and_targets(update)
    if not role:
        return await safe_send(update, context, "Usage: /assign <role name...> (reply / click-mention / IDs)")
    if not targets:
        return await safe_send(update, context, "Provide targets by replying, click-mentioning, or adding numeric IDs.")

    data = load_data()
    chat = ensure_chat(data, str(update.effective_chat.id))

    if role not in chat["roles"]:
        return await safe_send(update, context, f"Role '{role}' doesn't exist. Create it first with /createrole.")

    assigned, already = [], []

    # Also record the actor's user info (helps if you later want)
    upsert_user(chat, update.effective_user.id, update.effective_user.first_name or "User", update.effective_user.username)

    for uid, label in targets:
        uid_str = str(uid)
        chat["assignments"].setdefault(uid_str, [])

        # store best-known name for tagging without API calls
        if label.startswith("ID "):
            # if we only got a numeric id, keep any previous stored name or set generic
            prev = chat["users"].get(uid_str, {}).get("name")
            upsert_user(chat, uid, prev or f"User {uid}", None)
        else:
            upsert_user(chat, uid, label, None)

        if role in chat["assignments"][uid_str]:
            already.append(label)
        else:
            chat["assignments"][uid_str].append(role)
            assigned.append(label)

    save_data(data)

    lines = []
    if assigned:
        lines.append(f"Assigned '{role}' to: {', '.join(assigned)}")
    if already:
        lines.append(f"Already had role: {', '.join(already)}")
    await safe_send(update, context, "\n".join(lines) if lines else "No changes made.")

async def unassign(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_admin(update, context):
        return await safe_send(update, context, "Only admins can remove roles.")

    role, targets = parse_role_and_targets(update)
    if not role:
        return await safe_send(update, context, "Usage: /unassign <role name...> (reply / click-mention / IDs)")
    if not targets:
        return await safe_send(update, context, "Provide targets by replying, click-mentioning, or adding numeric IDs.")

    data = load_data()
    chat = ensure_chat(data, str(update.effective_chat.id))

    removed, missing = [], []
    for uid, label in targets:
        uid_str = str(uid)
        if uid_str not in chat["assignments"] or role not in chat["assignments"][uid_str]:
            missing.append(label)
            continue
        chat["assignments"][uid_str].remove(role)
        if not chat["assignments"][uid_str]:
            del chat["assignments"][uid_str]
        removed.append(label)

    save_data(data)

    lines = []
    if removed:
        lines.append(f"Removed '{role}' from: {', '.join(removed)}")
    if missing:
        lines.append(f"Did not have '{role}': {', '.join(missing)}")
    await safe_send(update, context, "\n".join(lines) if lines else "No changes made.")

async def roles(update: Update, context: ContextTypes.DEFAULT_TYPE):
    data = load_data()
    chat = ensure_chat(data, str(update.effective_chat.id))
    role_list = sorted(chat["roles"].keys())
    if not role_list:
        return await safe_send(update, context, "No roles created yet. Use /createrole <name>.")
    await safe_send(update, context, "Roles:\n" + "\n".join(f"  • {r}" for r in role_list))

async def myroles(update: Update, context: ContextTypes.DEFAULT_TYPE):
    data = load_data()
    chat = ensure_chat(data, str(update.effective_chat.id))
    uid = str(update.effective_user.id)
    r = sorted(chat["assignments"].get(uid, []))
    if not r:
        return await safe_send(update, context, "You have no roles.")
    await safe_send(update, context, "Your roles:\n" + "\n".join(f"  • {x}" for x in r))

async def tag(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await safe_send(update, context, "Usage: /tag <role name...>\nExample: /tag moderators")

    role = norm_role(" ".join(context.args))
    data = load_data()
    chat = ensure_chat(data, str(update.effective_chat.id))

    if role not in chat["roles"]:
        return await safe_send(update, context, f"Role '{role}' doesn't exist.")

    users_with_role = [uid for uid, roles_ in chat["assignments"].items() if role in roles_]
    if not users_with_role:
        return await safe_send(update, context, f"No one has the '{role}' role yet.")

    mentions = []
    for uid in users_with_role:
        name = chat["users"].get(uid, {}).get("name") or f"User {uid}"
        mentions.append(f'<a href="tg://user?id={uid}">{html_escape(name)}</a>')

    text = f"<b>@{html_escape(role)}</b> ({len(mentions)} members):\n" + " ".join(mentions)
    await safe_send(update, context, text, html=True)

def main():
    if not TOKEN:
        raise RuntimeError("Missing TELEGRAM_BOT_TOKEN environment variable.")

    app = Application.builder().token(TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", start))
    app.add_handler(CommandHandler("createrole", createrole))
    app.add_handler(CommandHandler("deleterole", deleterole))
    app.add_handler(CommandHandler("assign", assign))
    app.add_handler(CommandHandler("unassign", unassign))
    app.add_handler(CommandHandler("roles", roles))
    app.add_handler(CommandHandler("myroles", myroles))
    app.add_handler(CommandHandler("tag", tag))

    app.add_error_handler(error_handler)

    logger.info("Bot starting...")
    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)

if __name__ == "__main__":
    main()
