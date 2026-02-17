import json
import os
import logging
import traceback
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from telegram.constants import ParseMode

# --- Config ---
TOKEN = "8457747048:AAFwiPCR274Tg9UKvA9Skial6MTfw-JXxgc"
DATA_FILE = os.path.join(os.path.dirname(__file__), "roles_data.json")

logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Data helpers ---
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

def get_chat_data(chat_id: str):
    data = load_data()
    if chat_id not in data:
        data[chat_id] = {"roles": {}, "assignments": {}}
        save_data(data)
    return data, data[chat_id]

# --- Safe reply helper ---
async def reply(update: Update, text: str, parse_mode=None):
    """Send a message to the chat. Handles forum/topic groups."""
    chat_id = update.effective_chat.id
    thread_id = getattr(update.message, "message_thread_id", None)
    try:
        await update.message.reply_text(text, parse_mode=parse_mode)
    except Exception:
        try:
            kwargs = {"chat_id": chat_id, "text": text}
            if parse_mode:
                kwargs["parse_mode"] = parse_mode
            if thread_id:
                kwargs["message_thread_id"] = thread_id
            await update.get_bot().send_message(**kwargs)
        except Exception:
            try:
                await update.get_bot().send_message(chat_id=chat_id, text=text)
            except Exception as e:
                logger.error(f"Failed to send message to {chat_id}: {e}")

# --- Helpers ---
async def check_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if update.effective_chat.type == "private":
        return True
    try:
        member = await context.bot.get_chat_member(update.effective_chat.id, update.effective_user.id)
        return member.status in ("administrator", "creator")
    except Exception as e:
        logger.error(f"Admin check failed: {e}")
        return False

# --- Error handler ---
async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Exception while handling update: {context.error}")
    logger.error(traceback.format_exc())

# --- Commands ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.info(f"Received /start from {update.effective_user.id} in chat {update.effective_chat.id} (type: {update.effective_chat.type})")
    await reply(update,
        "Role Bot — Manage roles in your group.\n\n"
        "Admin commands:\n"
        "  /createrole <name> — Create a role\n"
        "  /deleterole <name> — Delete a role\n"
        "  /assign <role> <@user1 @user2...> — Assign role\n"
        "  /unassign <role> <@user or reply> — Remove a role\n\n"
        "Everyone:\n"
        "  /roles — List all roles\n"
        "  /myroles — See your roles\n"
        "  /tag <role> — TAG everyone with a role"
    )

async def createrole(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.info(f"Received /createrole from {update.effective_user.id}")
    if not await check_admin(update, context):
        return await reply(update, "Only admins can create roles.")
    if not context.args:
        return await reply(update, "Usage: /createrole <name>")
    role_name = " ".join(context.args).strip().lower()
    chat_id = str(update.effective_chat.id)
    data, chat = get_chat_data(chat_id)
    if role_name in chat["roles"]:
        return await reply(update, f"Role '{role_name}' already exists.")
    chat["roles"][role_name] = True
    save_data(data)
    await reply(update, f"Role '{role_name}' created.")

async def deleterole(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.info(f"Received /deleterole from {update.effective_user.id}")
    if not await check_admin(update, context):
        return await reply(update, "Only admins can delete roles.")
    if not context.args:
        return await reply(update, "Usage: /deleterole <name>")
    role_name = " ".join(context.args).strip().lower()
    chat_id = str(update.effective_chat.id)
    data, chat = get_chat_data(chat_id)
    if role_name not in chat["roles"]:
        return await reply(update, f"Role '{role_name}' doesn't exist.")
    del chat["roles"][role_name]
    for uid in list(chat["assignments"]):
        if role_name in chat["assignments"][uid]:
            chat["assignments"][uid].remove(role_name)
    save_data(data)
    await reply(update, f"Role '{role_name}' deleted.")

def resolve_target_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.reply_to_message:
        u = update.message.reply_to_message.from_user
        return str(u.id), u.first_name
    if context.args and len(context.args) >= 2:
        for ent in (update.message.entities or []):
            if ent.type == "text_mention":
                return str(ent.user.id), ent.user.first_name
            if ent.type == "mention":
                username = update.message.text[ent.offset + 1 : ent.offset + ent.length]
                return username, f"@{username}"
    return None, None

async def assign(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.info(f"Received /assign from {update.effective_user.id}")
    if not await check_admin(update, context):
        return await reply(update, "Only admins can assign roles.")
    if not context.args:
        return await reply(update, "Usage: /assign <role> <@user1 @user2 ... or reply>")
    role_name = context.args[0].strip().lower()
    chat_id = str(update.effective_chat.id)
    data, chat = get_chat_data(chat_id)
    if role_name not in chat["roles"]:
        return await reply(update, f"Role '{role_name}' doesn't exist. Create it first.")

    target_users = []
    if update.message.reply_to_message:
        u = update.message.reply_to_message.from_user
        target_users.append((str(u.id), u.first_name))
    if update.message.entities:
        for ent in update.message.entities:
            if ent.type == "text_mention" and ent.user:
                target_users.append((str(ent.user.id), ent.user.first_name))
            elif ent.type == "mention":
                username = update.message.text[ent.offset + 1 : ent.offset + ent.length]
                target_users.append((username, f"@{username}"))

    if not target_users:
        return await reply(update, "Reply to a user or mention them: /assign <role> @user1 @user2")

    assigned = []
    already_had = []
    for target_id, target_name in target_users:
        if target_id not in chat["assignments"]:
            chat["assignments"][target_id] = []
        if role_name in chat["assignments"][target_id]:
            already_had.append(target_name)
        else:
            chat["assignments"][target_id].append(role_name)
            assigned.append(target_name)
    save_data(data)

    msg = []
    if assigned:
        msg.append(f"Assigned '{role_name}' to: {', '.join(assigned)}")
    if already_had:
        msg.append(f"Already had role: {', '.join(already_had)}")
    await reply(update, "\n".join(msg) if msg else "No changes made.")

async def unassign(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.info(f"Received /unassign from {update.effective_user.id}")
    if not await check_admin(update, context):
        return await reply(update, "Only admins can remove roles.")
    if not context.args:
        return await reply(update, "Usage: /unassign <role> <@user or reply>")
    role_name = context.args[0].strip().lower()
    chat_id = str(update.effective_chat.id)
    data, chat = get_chat_data(chat_id)
    target_id, target_name = resolve_target_user(update, context)
    if not target_id:
        return await reply(update, "Reply to a user or mention them.")
    if target_id not in chat["assignments"] or role_name not in chat["assignments"][target_id]:
        return await reply(update, f"{target_name} doesn't have role '{role_name}'.")
    chat["assignments"][target_id].remove(role_name)
    save_data(data)
    await reply(update, f"Removed '{role_name}' from {target_name}.")

async def roles(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    data, chat = get_chat_data(chat_id)
    role_list = list(chat["roles"].keys())
    if not role_list:
        return await reply(update, "No roles created yet. Use /createrole <name>.")
    await reply(update, "Roles:\n" + "\n".join(f"  - {r}" for r in sorted(role_list)))

async def myroles(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    user_id = str(update.effective_user.id)
    data, chat = get_chat_data(chat_id)
    user_roles = chat["assignments"].get(user_id, [])
    if not user_roles:
        return await reply(update, "You have no roles.")
    await reply(update, "Your roles:\n" + "\n".join(f"  - {r}" for r in sorted(user_roles)))

async def tag(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.info(f"Received /tag from {update.effective_user.id} in chat {update.effective_chat.id}")
    if not context.args:
        return await reply(update, "Usage: /tag <role>\nExample: /tag moderators")
    role_name = " ".join(context.args).strip().lower()
    chat_id = str(update.effective_chat.id)
    data, chat = get_chat_data(chat_id)

    if role_name not in chat["roles"]:
        return await reply(update, f"Role '{role_name}' doesn't exist.")

    users_with_role = [uid for uid, r in chat["assignments"].items() if role_name in r]

    if not users_with_role:
        return await reply(update, f"No one has the '{role_name}' role yet.")

    # Build HTML mentions - this is the RELIABLE way to tag users in Telegram
    mentions = []
    for uid in users_with_role:
        try:
            uid_int = int(uid)
            # Get user info for their real name
            member = await context.bot.get_chat_member(int(chat_id), uid_int)
            name = member.user.first_name or "User"
            mentions.append(f'<a href="tg://user?id={uid_int}">{name}</a>')
        except (ValueError, Exception) as e:
            logger.warning(f"Could not resolve user {uid}: {e}")
            # uid might be a @username string
            if not uid.isdigit():
                mentions.append(f"@{uid}")
            else:
                mentions.append(f'<a href="tg://user?id={uid}">User {uid}</a>')

    message = f"<b>@{role_name}</b> ({len(mentions)}):\n" + " ".join(mentions)
    thread_id = getattr(update.message, "message_thread_id", None)

    try:
        kwargs = {
            "chat_id": update.effective_chat.id,
            "text": message,
            "parse_mode": ParseMode.HTML,
        }
        if thread_id:
            kwargs["message_thread_id"] = thread_id
        await context.bot.send_message(**kwargs)
    except Exception as e:
        logger.error(f"Failed to send HTML tag: {e}")
        # Fallback: try without parse mode
        fallback = f"@{role_name}: " + " ".join(mentions)
        await reply(update, fallback)

# --- Main ---
def main():
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

