import asyncio
import json
import re
import os
import logging
import threading
import queue
import sys
import random
import sqlite3
import webbrowser
from datetime import datetime
from typing import Optional, Dict, List, Union, Any, Set

import aiohttp
import customtkinter as ctk
from pyrogram import Client
from pyrogram.errors import FloodWait
from cryptography.fernet import Fernet
import pystray
from PIL import Image, ImageDraw
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib

matplotlib.use("TkAgg")

log_queue = queue.Queue()
stop_event = threading.Event()
DB_FILE = "bot_data.db"
KEY_FILE = "secret.key"
CONFIG_FILE = "config.enc"

ctk.set_appearance_mode("Dark")
DEFAULT_ACCENT = "#9D00FF"

#  ОБНОВЛЕННЫЙ ЛОГГЕР ЦВЕТОВ 
class QueueHandler(logging.Handler):
    def emit(self, record):
        msg = self.format(record)
        log_queue.put((record.levelname, msg))

def setup_logger():
    logger = logging.getLogger("BotLogger")
    logger.setLevel(logging.INFO)
    if logger.handlers: logger.handlers = []
    handler = QueueHandler()
    formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

logger = setup_logger()

class SecurityManager:
    def __init__(self):
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)

    def _load_or_create_key(self):
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(KEY_FILE, "wb") as f:
                f.write(key)
            return key

    def save_config(self, data: dict):
        try:
            json_data = json.dumps(data)
            encrypted_data = self.cipher.encrypt(json_data.encode())
            with open(CONFIG_FILE, "wb") as f:
                f.write(encrypted_data)
        except Exception as e:
            logger.error(f"Save Config Error: {e}")

    def load_config(self) -> dict:
        if not os.path.exists(CONFIG_FILE):
            return {}
        try:
            with open(CONFIG_FILE, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = self.cipher.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            logger.error(f"Ошибка дешифровки конфига: {e}")
            return {}

class DatabaseManager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._init_db()

    def _init_db(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS processed_posts (
                post_id INTEGER PRIMARY KEY,
                date_added TEXT
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                stars_count INTEGER,
                channel TEXT
            )
        """)
        self.conn.commit()

    def is_processed(self, post_id: int) -> bool:
        self.cursor.execute("SELECT 1 FROM processed_posts WHERE post_id = ?", (post_id,))
        return self.cursor.fetchone() is not None

    def mark_processed(self, post_id: int):
        try:
            self.cursor.execute("INSERT OR IGNORE INTO processed_posts (post_id, date_added) VALUES (?, ?)", 
                                (post_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            self.conn.commit()
        except Exception as e:
            logger.error(f"DB Error: {e}")

    def log_transaction(self, stars: int, channel: str):
        self.cursor.execute("INSERT INTO stats (timestamp, stars_count, channel) VALUES (?, ?, ?)",
                            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), stars, channel))
        self.conn.commit()

    def get_stats_data(self):
        self.cursor.execute("""
            SELECT date(timestamp), SUM(stars_count) 
            FROM stats 
            GROUP BY date(timestamp) 
            ORDER BY date(timestamp) DESC LIMIT 7
        """)
        return self.cursor.fetchall()

    def get_total_stars(self):
        self.cursor.execute("SELECT SUM(stars_count) FROM stats")
        result = self.cursor.fetchone()[0]
        return result if result else 0

class LolzAPI:
    def __init__(self, token: str):
        self.base_url = "https://prod-api.lolz.live"
        self.headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async def _request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict]:
        url = f"{self.base_url}{endpoint}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(method, url, headers=self.headers, **kwargs) as response:
                    if response.status == 200: return await response.json()
                    if response.status == 429:
                        logger.warning("Lolz API Rate Limit (429). Waiting 5s...")
                        await asyncio.sleep(5)
                        return await self._request(method, endpoint, **kwargs)
                    return None
        except: return None

    async def get_thread_posts(self, thread_id, page=1):
        params = {"thread_id": thread_id, "page": page, "order": "post_date_reverse"}
        data = await self._request("GET", "/posts", params=params)
        return data.get("posts", []) if data else [], page

    async def has_comments(self, post_id):
        data = await self._request("GET", "/posts/comments", params={"post_id": post_id})
        return len(data.get("comments", [])) > 0 if data else False

    async def create_comment(self, post_id, text):
        await self._request("POST", f"/posts/{post_id}/comments", json={"comment_body": text})

class TelegramLinkExtractor:
    @staticmethod
    def extract(text: str) -> List[str]:
        if not text: return []
        patterns = [
            r'https?://(?:www\.)?(?:t\.me||telegram\.me)/([a-zA-Z0-9_]+(?:/\d+)?)',
            r'\[MEDIA=telegram\]([a-zA-Z0-9_]+(?:/\d+)?)\[/MEDIA\]',
            r'data-telegram-post="([a-zA-Z0-9_]+/\d+)"'
        ]
        all_matches = {f"https://t.me/{match}" for p in patterns for match in re.findall(p, text, re.I)}
        return list(all_matches)

    @staticmethod
    def parse(link: str) -> Optional[tuple[str, Optional[int]]]:
        match = re.search(r't\.me/([^/]+)(?:/(\d+))?', link)
        if match:
            channel = match.group(1)
            message_id = int(match.group(2)) if match.group(2) else None
            return channel, message_id
        return None

class TelegramStarsBot:
    def __init__(self, config: dict, db: DatabaseManager):
        self.config = config
        self.db = db
        self.lolz = LolzAPI(config["lolz_token"])
        self.client: Optional[Client] = None
        try:
            self.start_page = int(config.get("start_page", 1))
        except:
            self.start_page = 1

    async def notify_admin(self, message: str):
        if not self.config.get("admin_notify", False): return
        if self.config.get("bot_token") and self.config.get("admin_id"):
            try:
                url = f"https://api.telegram.org/bot{self.config['bot_token']}/sendMessage"
                payload = {"chat_id": self.config["admin_id"], "text": f"🤖 {message}", "parse_mode": "HTML"}
                async with aiohttp.ClientSession() as session:
                    await session.post(url, json=payload)
            except Exception as e: logger.error(f"Notify Error: {e}")
        else:
            try:
                target = self.config.get("admin_id") or "me"
                await self.client.send_message(target, f"🤖 {message}")
            except: pass

    async def send_stars_reaction(self, channel: str, message_id: Optional[int] = None) -> bool:
        if not hasattr(self.client, 'send_paid_reaction'):
            logger.error("Ошибка: Обновите библиотеку! pip install -U pyrofork")
            return False
        
        try:
            if message_id is None:
                async for message in self.client.get_chat_history(f"@{channel}", limit=1):
                    message_id = message.id
                    break
                if message_id is None: return False
            
            await self.client.send_paid_reaction(f"@{channel}", message_id, int(self.config["stars_count"]))
            self.db.log_transaction(int(self.config["stars_count"]), channel)
            logger.info(f"✅ Отправлено {self.config['stars_count']} звезд в @{channel}")
            await self.notify_admin(f"✅ Отправлено <b>{self.config['stars_count']}</b> ⭐️ в @{channel}")
            return True
        except FloodWait as e:
            logger.warning(f"FloodWait: ожидание {e.x} сек.")
            await asyncio.sleep(e.x + 2)
            return False
        except Exception as e:
            logger.error(f"Ошибка отправки (@{channel}): {e}")
            return False

    async def _process_single_post(self, post: Dict[str, Any]):
        post_id = post.get("post_id")
        if not post_id or self.db.is_processed(post_id): return
        
        logger.info(f"🔍 Проверка поста ID: {post_id}")
        
        if self.config["skip_comments"]:
            if await self.lolz.has_comments(post_id):
                logger.info(f"⏭️ Пропуск {post_id} (уже есть ответы)")
                self.db.mark_processed(post_id)
                return
        
        post_content = post.get('post_body_html') or post.get('post_body')
        if not post_content:
            self.db.mark_processed(post_id); return

        links = TelegramLinkExtractor.extract(post_content)
        if not links:
            self.db.mark_processed(post_id); return

        successful_reactions = 0
        for link in links:
            if stop_event.is_set(): break
            parsed_link = TelegramLinkExtractor.parse(link)
            if parsed_link:
                channel, message_id = parsed_link
                if await self.send_stars_reaction(channel, message_id):
                    successful_reactions += 1
                await asyncio.sleep(1)
        
        if successful_reactions > 0 and self.config["enable_reply"]:
            await asyncio.sleep(int(self.config["api_delay"]))
            replies = self.config.get("reply_templates", "Done").split("||")
            reply_message = random.choice(replies).strip()
            await self.lolz.create_comment(post_id, reply_message)

        self.db.mark_processed(post_id)
        logger.info(f"✅ Пост {post_id} обработан.")

    async def process(self):
        logger.info(f"🚀 Бот запущен. Страница: {self.start_page}")
        self.client = Client("secure_session", api_id=self.config["api_id"], api_hash=self.config["api_hash"])
        try:
            await self.client.start()
        except Exception as e:
            logger.error(f"Ошибка авторизации: {e}")
            return

        while not stop_event.is_set():
            try:
                posts, _ = await self.lolz.get_thread_posts(self.config["forum_thread_id"], self.start_page)
                if posts:
                    logger.info(f"📄 Обработка страницы {self.start_page}...")
                    for post in reversed(posts):
                        if stop_event.is_set(): break
                        await self._process_single_post(post)
                    self.start_page += 1
                    logger.info(f"➡️ Переход на страницу: {self.start_page}")
                else:
                    logger.info(f"💤 Страница {self.start_page} пуста. Ожидание...")
                    for _ in range(int(self.config["check_interval"])):
                        if stop_event.is_set(): break
                        await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"Ошибка цикла: {e}"); await asyncio.sleep(5)

        if self.client and self.client.is_connected: await self.client.stop()
        logger.info("🛑 Бот остановлен.")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.security = SecurityManager()
        self.db = DatabaseManager()
        self.title("B1ack Stars v1.1 [lolz.live/b1ackcloud]")
        self.geometry("1000x750")
        self.accent_color = DEFAULT_ACCENT
        self.config = self.security.load_config()

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._init_sidebar()
        self._init_pages()
        self._load_config_to_ui()
        self.after(100, self.update_logs)

    def _init_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(7, weight=1)

        ctk.CTkLabel(self.sidebar, text="B1ack Stars", font=("Impact", 24), text_color=self.accent_color).pack(pady=20)
        self.btns = {}
        for name, cmd in [("Дашборд", self.show_dashboard), ("Настройки", self.show_settings), 
                          ("Консоль", self.show_console), ("Визуал", self.show_theme)]:
            btn = ctk.CTkButton(self.sidebar, text=name, command=cmd, fg_color="transparent", 
                                border_width=1, border_color=self.accent_color)
            btn.pack(pady=5, padx=10, fill="x")
            self.btns[name] = btn

        ctk.CTkLabel(self.sidebar, text="CONTROL", font=("Arial", 10, "bold"), text_color="gray").pack(pady=(20,5))
        self.btn_start = ctk.CTkButton(self.sidebar, text="START BOT", fg_color="green", command=self.start_bot)
        self.btn_start.pack(pady=5, padx=10, fill="x")
        self.btn_stop = ctk.CTkButton(self.sidebar, text="STOP", fg_color="#330000", state="disabled", command=self.stop_bot)
        self.btn_stop.pack(pady=5, padx=10, fill="x")

        self.btn_bug = ctk.CTkButton(self.sidebar, text="🐞 Сообщить о баге", fg_color="transparent", 
                                     text_color="#FF5555", hover_color="#331111", command=self.open_support)
        self.btn_bug.pack(pady=(20, 5), padx=10, fill="x", side="bottom")
        self.btn_tray = ctk.CTkButton(self.sidebar, text="⬇ В трей", fg_color="gray20", command=self.minimize_to_tray)
        self.btn_tray.pack(pady=(5, 20), padx=10, fill="x", side="bottom")

    def open_support(self):
        webbrowser.open("https://t.me/B1ackCloudSupp")

    def _init_pages(self):
        self.frame_dash = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.stats_container = ctk.CTkFrame(self.frame_dash, fg_color="transparent")
        self.stats_container.pack(fill="x", padx=20, pady=20)

        self.box_left = ctk.CTkFrame(self.stats_container, fg_color="#181818", corner_radius=10)
        self.box_left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        self.lbl_total_stars = ctk.CTkLabel(self.box_left, text="0", font=("Arial", 40, "bold"), text_color=self.accent_color)
        self.lbl_total_stars.pack(pady=(20, 5))
        ctk.CTkLabel(self.box_left, text="Всего отправлено звезд", font=("Arial", 12, "bold"), text_color="gray60").pack(pady=(0, 20))

        self.box_right = ctk.CTkFrame(self.stats_container, fg_color="#181818", corner_radius=10)
        self.box_right.pack(side="right", fill="both", expand=True, padx=(10, 0))
        self.lbl_money = ctk.CTkLabel(self.box_right, text="$0.00", font=("Arial", 40, "bold"), text_color="#00FF00")
        self.lbl_money.pack(pady=(20, 5))
        ctk.CTkLabel(self.box_right, text="Примерная стоимость (USD)", font=("Arial", 12, "bold"), text_color="gray60").pack(pady=(0, 20))

        self.graph_frame = ctk.CTkFrame(self.frame_dash)
        self.graph_frame.pack(fill="both", expand=True, padx=20, pady=(10, 20))

        self.frame_settings = ctk.CTkScrollableFrame(self, corner_radius=0, label_text="Настройки")
        self.entries = {}
        fields = [
            ("api_id", "API ID"), ("api_hash", "API Hash"), ("lolz_token", "Lolz Token"),
            ("forum_thread_id", "Thread ID"), ("admin_id", "TG User ID"),
            ("bot_token", "Bot Token"), ("start_page", "Start Page"),
            ("stars_count", "Кол-во звезд"), ("reply_templates", "Ответы (||)")
        ]
        for k, name in fields:
            ctk.CTkLabel(self.frame_settings, text=name, anchor="w").pack(fill="x", padx=10)
            e = ctk.CTkEntry(self.frame_settings); e.pack(fill="x", padx=10, pady=(0, 10)); self.entries[k] = e
        
        self.chk_reply = ctk.CTkCheckBox(self.frame_settings, text="Отвечать в теме")
        self.chk_reply.pack(anchor="w", padx=10)
        self.chk_skip = ctk.CTkCheckBox(self.frame_settings, text="Пропускать с ответом")
        self.chk_skip.pack(anchor="w", padx=10, pady=10)
        self.chk_notify = ctk.CTkCheckBox(self.frame_settings, text="Уведомлять в TG")
        self.chk_notify.pack(anchor="w", padx=10)
        ctk.CTkButton(self.frame_settings, text="Сохранить", command=self.save_config).pack(pady=20)

        # КОНСОЛЬ С ЦВЕТАМИ
        self.frame_console = ctk.CTkFrame(self, corner_radius=0)
        self.console = ctk.CTkTextbox(self.frame_console, font=("Consolas", 12), fg_color="#050505")
        self.console.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.console._textbox.tag_config("INFO", foreground="#FFFFFF")
        self.console._textbox.tag_config("ERROR", foreground="#FF4444")
        self.console._textbox.tag_config("WARNING", foreground="#FFFF00")
        self.console._textbox.tag_config("SUCCESS", foreground="#00FF00")
        self.console._textbox.tag_config("STEP", foreground="#55AAFF")

        self.frame_theme = ctk.CTkFrame(self, corner_radius=0)
        ctk.CTkLabel(self.frame_theme, text="Цвет интерфейса", font=("Arial", 16)).pack(pady=20)
        self.slider_r = ctk.CTkSlider(self.frame_theme, from_=0, to=255, command=self.update_color_preview); self.slider_r.pack(pady=10)
        self.slider_g = ctk.CTkSlider(self.frame_theme, from_=0, to=255, command=self.update_color_preview); self.slider_g.pack(pady=10)
        self.slider_b = ctk.CTkSlider(self.frame_theme, from_=0, to=255, command=self.update_color_preview); self.slider_b.pack(pady=10)
        self.color_preview = ctk.CTkButton(self.frame_theme, text="ПРИМЕНИТЬ", command=self.apply_theme); self.color_preview.pack(pady=20)
        self.show_dashboard()

    def switch_frame(self, frame):
        for f in [self.frame_dash, self.frame_settings, self.frame_console, self.frame_theme]: f.grid_forget()
        frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

    def show_dashboard(self): self.switch_frame(self.frame_dash); self.draw_stats()
    def show_settings(self): self.switch_frame(self.frame_settings)
    def show_console(self): self.switch_frame(self.frame_console)
    def show_theme(self): self.switch_frame(self.frame_theme)

    def update_color_preview(self, _=None):
        r, g, b = int(self.slider_r.get()), int(self.slider_g.get()), int(self.slider_b.get())
        self.color_preview.configure(fg_color=f"#{r:02x}{g:02x}{b:02x}")

    def apply_theme(self):
        r, g, b = int(self.slider_r.get()), int(self.slider_g.get()), int(self.slider_b.get())
        self.accent_color = f"#{r:02x}{g:02x}{b:02x}"
        self.sidebar.winfo_children()[0].configure(text_color=self.accent_color)
        self.lbl_total_stars.configure(text_color=self.accent_color)
        for btn in self.btns.values(): btn.configure(border_color=self.accent_color)

    def draw_stats(self):
        for w in self.graph_frame.winfo_children(): w.destroy()
        data, total = self.db.get_stats_data(), self.db.get_total_stars()
        self.lbl_total_stars.configure(text=str(total)); self.lbl_money.configure(text=f"${total * 0.013:.2f}")
        if not data: return
        fig = plt.Figure(figsize=(5, 4), dpi=100, facecolor="#2b2b2b")
        ax = fig.add_subplot(111); ax.set_facecolor("#2b2b2b"); ax.plot([d[0] for d in data], [d[1] for d in data], marker='o', color=self.accent_color)
        ax.tick_params(colors='white'); canvas = FigureCanvasTkAgg(fig, master=self.graph_frame); canvas.draw(); canvas.get_tk_widget().pack(fill="both", expand=True)

    def save_config(self):
        cfg = {k: v.get() for k, v in self.entries.items()}
        cfg.update({"enable_reply": bool(self.chk_reply.get()), "skip_comments": bool(self.chk_skip.get()), 
                    "admin_notify": bool(self.chk_notify.get()), "check_interval": 30, "api_delay": 5})
        self.security.save_config(cfg); logger.info("✅ Конфигурация сохранена!")

    def _load_config_to_ui(self):
        if not self.config: return
        for k, e in self.entries.items():
            if k in self.config: e.insert(0, str(self.config[k]))
        if self.config.get("enable_reply"): self.chk_reply.select()
        if self.config.get("skip_comments"): self.chk_skip.select()
        if self.config.get("admin_notify"): self.chk_notify.select()

    def update_logs(self):
        while not log_queue.empty():
            level, msg = log_queue.get()
            tag = level
            if any(x in msg for x in ["✅", "⭐"]): tag = "SUCCESS"
            elif any(x in msg for x in ["🚀", "➡️", "📄", "🔍"]): tag = "STEP"
            self.console.insert("end", msg + "\n", tag)
            self.console.see("end")
        self.after(100, self.update_logs)

    def start_bot(self):
        self.save_config(); self.config = self.security.load_config()
        if not self.config.get("api_id"): return
        stop_event.clear(); self.btn_start.configure(state="disabled", fg_color="gray")
        self.btn_stop.configure(state="normal", fg_color="#FF3333"); self.show_console()
        threading.Thread(target=self._run_bot_process, daemon=True).start()

    def _run_bot_process(self):
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        bot = TelegramStarsBot(self.config, self.db); loop.run_until_complete(bot.process())

    def stop_bot(self):
        stop_event.set(); self.btn_start.configure(state="normal", fg_color="green")
        self.btn_stop.configure(state="disabled", fg_color="#330000"); logger.warning("🛑 Остановка...")

    def minimize_to_tray(self):
        self.withdraw(); image = Image.new('RGB', (64, 64), color=(73, 109, 137))
        d = ImageDraw.Draw(image); d.text((10,10), "S", fill=(255,255,0))
        menu = pystray.Menu(pystray.MenuItem("Открыть", self.show_window), pystray.MenuItem("Выход", self.quit_app))
        self.tray_icon = pystray.Icon("name", image, "B1ackStars", menu); threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def show_window(self, icon, item): self.tray_icon.stop(); self.after(0, self.deiconify)
    def quit_app(self, icon, item): self.tray_icon.stop(); self.destroy(); sys.exit()

if __name__ == "__main__":
    app = App(); app.mainloop()
