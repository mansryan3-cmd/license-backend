import tkinter as tk
from tkinter import messagebox
import urllib.request
import urllib.error
import json
import os
import uuid
import hashlib
import platform
import winreg
import threading


# ============================================================
# CONFIG
# ============================================================

API_URL = "https://license-backend-2.onrender.com"

SESSION_FILE = "session.json"

APP_NAME = "RESOURCE HUB"


# ============================================================
# COLORS
# ============================================================

BG = "#050b14"
BG2 = "#081321"
SIDEBAR = "#07101c"
TOPBAR = "#08111d"

CARD = "#0c1928"
CARD_HOVER = "#102235"

INPUT = "#0a1725"

BORDER = "#17314a"

WHITE = "#eef8ff"
TEXT = "#d6e8f5"
MUTED = "#88a5b9"
DIM = "#58778e"

CYAN = "#38d5f5"
BLUE = "#4f9df7"
PURPLE = "#8d7cff"

GREEN = "#51d68b"
RED = "#ef718a"


# ============================================================
# API
# ============================================================

def api_request(
    endpoint,
    method="GET",
    data=None,
    token=None,
    timeout=20
):

    url = (
        API_URL.rstrip("/")
        + endpoint
    )

    headers = {
        "Content-Type":
            "application/json",
        "User-Agent":
            "ResourceHub/3.0"
    }

    if token:

        headers[
            "Authorization"
        ] = "Bearer " + token

    body = None

    if data is not None:

        body = json.dumps(
            data
        ).encode(
            "utf-8"
        )

    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method=method
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=timeout
        ) as response:

            raw = (
                response
                .read()
                .decode("utf-8")
            )

            return True, json.loads(
                raw
            )

    except urllib.error.HTTPError as error:

        try:

            raw = (
                error
                .read()
                .decode("utf-8")
            )

            data = json.loads(
                raw
            )

            return False, {
                "detail":
                    data.get(
                        "detail",
                        f"Server error {error.code}"
                    )
            }

        except Exception:

            return False, {
                "detail":
                    f"Server error {error.code}"
            }

    except urllib.error.URLError:

        return False, {
            "detail":
                "Unable to connect to the license server."
        }

    except Exception as error:

        return False, {
            "detail":
                str(error)
        }


# ============================================================
# HWID
# ============================================================

def get_hwid():

    try:

        registry_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography"
        )

        machine_guid, _ = (
            winreg.QueryValueEx(
                registry_key,
                "MachineGuid"
            )
        )

        winreg.CloseKey(
            registry_key
        )

        raw = str(
            machine_guid
        )

    except Exception:

        raw = (
            platform.node()
            + "|"
            + platform.system()
            + "|"
            + platform.machine()
            + "|"
            + str(uuid.getnode())
        )

    return hashlib.sha256(
        raw.encode(
            "utf-8"
        )
    ).hexdigest()


# ============================================================
# TIME
# ============================================================

def format_time(seconds):

    seconds = max(
        0,
        int(seconds)
    )

    days = seconds // 86400

    seconds %= 86400

    hours = seconds // 3600

    seconds %= 3600

    minutes = seconds // 60

    seconds %= 60

    if days:

        return (
            f"{days}d "
            f"{hours}h "
            f"{minutes}m"
        )

    if hours:

        return (
            f"{hours}h "
            f"{minutes}m "
            f"{seconds}s"
        )

    if minutes:

        return (
            f"{minutes}m "
            f"{seconds}s"
        )

    return f"{seconds}s"


# ============================================================
# APPLICATION
# ============================================================

class ResourceHub(tk.Tk):

    def __init__(self):

        super().__init__()

        self.title(
            APP_NAME
        )

        self.geometry(
            "1180x740"
        )

        self.minsize(
            950,
            600
        )

        self.configure(
            bg=BG
        )

        self.hwid = get_hwid()

        self.token = ""
        self.username = ""
        self.license_key = ""

        self.seconds_remaining = 0

        self.current_screen = "startup"

        self.selected_category = "Tools"

        self.tool_cards = []

        self.show_startup()


    # ========================================================
    # HELPERS
    # ========================================================

    def clear_screen(self):

        for widget in self.winfo_children():

            widget.destroy()


    def make_button(
        self,
        parent,
        text,
        command,
        bg=CYAN,
        fg="#031019",
        font=("Segoe UI", 10, "bold"),
        padx=18,
        pady=9
    ):

        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=bg,
            activeforeground=fg,
            relief="flat",
            bd=0,
            cursor="hand2",
            font=font,
            padx=padx,
            pady=pady
        )


    # ========================================================
    # STARTUP
    # ========================================================

    def show_startup(self):

        self.current_screen = "startup"

        self.clear_screen()

        center = tk.Frame(
            self,
            bg=BG
        )

        center.place(
            relx=0.5,
            rely=0.5,
            anchor="center"
        )


        tk.Label(
            center,
            text="◉",
            bg=BG,
            fg=CYAN,
            font=("Segoe UI", 48, "bold")
        ).pack()


        tk.Label(
            center,
            text="RESOURCE HUB",
            bg=BG,
            fg=WHITE,
            font=("Segoe UI", 25, "bold")
        ).pack()


        tk.Label(
            center,
            text="Secure client environment",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 10)
        ).pack(
            pady=(4, 22)
        )


        self.startup_label = tk.Label(
            center,
            text="Connecting to server...",
            bg=BG,
            fg=CYAN,
            font=("Segoe UI", 10)
        )

        self.startup_label.pack()


        self.after(
            200,
            self.startup_check
        )


    def startup_check(self):

        success, response = api_request(
            "/health",
            timeout=10
        )

        if not success:

            self.startup_label.config(
                text="Server unavailable",
                fg=RED
            )

            self.after(
                1200,
                lambda:
                    self.show_login(
                        "Unable to connect to the server."
                    )
            )

            return


        self.startup_label.config(
            text="Server connected"
        )

        self.after(
            400,
            self.check_session
        )


    # ========================================================
    # SESSION FILE
    # ========================================================

    def session_path(self):

        appdata = os.getenv(
            "LOCALAPPDATA"
        )

        if appdata:

            folder = os.path.join(
                appdata,
                "ResourceHub"
            )

        else:

            folder = os.path.join(
                os.path.expanduser("~"),
                "ResourceHub"
            )

        os.makedirs(
            folder,
            exist_ok=True
        )

        return os.path.join(
            folder,
            SESSION_FILE
        )


    def save_session(self):

        try:

            with open(
                self.session_path(),
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    {
                        "token": self.token
                    },
                    file
                )

        except Exception:
            pass


    def remove_session(self):

        try:

            path = self.session_path()

            if os.path.exists(path):

                os.remove(
                    path
                )

        except Exception:
            pass


    # ========================================================
    # SESSION CHECK
    # ========================================================

    def check_session(self):

        path = self.session_path()

        if not os.path.exists(path):

            self.show_login()

            return


        try:

            with open(
                path,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(
                    file
                )

            token = data.get(
                "token",
                ""
            )

            if not token:

                self.show_login()

                return


            success, response = (
                api_request(
                    "/api/auth/me",
                    token=token
                )
            )


            if not success:

                self.remove_session()

                self.show_login()

                return


            self.token = token

            self.username = (
                response[
                    "account"
                ][
                    "username"
                ]
            )


            license_data = (
                response[
                    "account"
                ].get(
                    "license"
                )
            )


            if license_data:

                self.license_key = (
                    license_data[
                        "license_key"
                    ]
                )

                self.seconds_remaining = int(
                    license_data.get(
                        "seconds_remaining",
                        0
                    )
                )

                if (
                    license_data.get(
                        "status"
                    ) == "active"
                    and
                    self.seconds_remaining > 0
                ):

                    self.show_dashboard()

                    return


            self.show_activate_screen()


        except Exception:

            self.remove_session()

            self.show_login()


    # ========================================================
    # LOGIN / REGISTER
    # ========================================================

    def show_login(
        self,
        error_message=""
    ):

        self.current_screen = "login"

        self.clear_screen()

        self.title(
            "Resource Hub — Account"
        )

        self.geometry(
            "760x650"
        )


        outer = tk.Frame(
            self,
            bg=BG
        )

        outer.pack(
            fill="both",
            expand=True,
            padx=80,
            pady=45
        )


        # LOGO

        tk.Label(
            outer,
            text="◉",
            bg=BG,
            fg=CYAN,
            font=("Segoe UI", 36, "bold")
        ).pack(
            anchor="w"
        )


        tk.Label(
            outer,
            text="RESOURCE HUB",
            bg=BG,
            fg=WHITE,
            font=("Segoe UI", 25, "bold")
        ).pack(
            anchor="w"
        )


        tk.Label(
            outer,
            text="Sign in to your private workspace",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 10)
        ).pack(
            anchor="w",
            pady=(4, 25)
        )


        # CARD

        card = tk.Frame(
            outer,
            bg=CARD,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        card.pack(
            fill="x"
        )


        tk.Label(
            card,
            text="ACCOUNT LOGIN",
            bg=CARD,
            fg=TEXT,
            font=("Segoe UI", 13, "bold")
        ).pack(
            anchor="w",
            padx=28,
            pady=(25, 18)
        )


        # USERNAME

        tk.Label(
            card,
            text="USERNAME",
            bg=CARD,
            fg=TEXT,
            font=("Segoe UI", 9, "bold")
        ).pack(
            anchor="w",
            padx=28
        )


        self.username_entry = tk.Entry(
            card,
            bg=INPUT,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=CYAN,
            font=("Segoe UI", 10)
        )

        self.username_entry.pack(
            fill="x",
            padx=28,
            pady=(7, 15),
            ipady=10
        )


        # PASSWORD

        tk.Label(
            card,
            text="PASSWORD",
            bg=CARD,
            fg=TEXT,
            font=("Segoe UI", 9, "bold")
        ).pack(
            anchor="w",
            padx=28
        )


        self.password_entry = tk.Entry(
            card,
            bg=INPUT,
            fg=TEXT,
            insertbackground=TEXT,
            show="•",
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=CYAN,
            font=("Segoe UI", 10)
        )

        self.password_entry.pack(
            fill="x",
            padx=28,
            pady=(7, 18),
            ipady=10
        )


        self.password_entry.bind(
            "<Return>",
            lambda event:
                self.login()
        )


        # LOGIN

        self.login_button = self.make_button(
            card,
            "SIGN IN",
            self.login,
            CYAN,
            "#031019",
            padx=30,
            pady=11
        )

        self.login_button.pack(
            anchor="w",
            padx=28
        )


        # REGISTER

        self.make_button(
            card,
            "CREATE ACCOUNT",
            self.register,
            "#16283a",
            CYAN,
            padx=25,
            pady=10
        ).pack(
            anchor="w",
            padx=28,
            pady=(10, 20)
        )


        # ERROR

        if error_message:

            tk.Label(
                outer,
                text=error_message,
                bg=BG,
                fg=RED,
                font=("Segoe UI", 9)
            ).pack(
                anchor="w",
                pady=(15, 0)
            )


    # ========================================================
    # LOGIN
    # ========================================================

    def login(self):

        username = (
            self.username_entry
            .get()
            .strip()
        )

        password = (
            self.password_entry
            .get()
        )


        if not username or not password:

            messagebox.showwarning(
                "Login",
                "Enter your username and password."
            )

            return


        self.login_button.config(
            text="SIGNING IN...",
            state="disabled"
        )


        threading.Thread(
            target=self.login_request,
            args=(
                username,
                password
            ),
            daemon=True
        ).start()


    def login_request(
        self,
        username,
        password
    ):

        success, response = api_request(
            "/api/auth/login",
            method="POST",
            data={
                "username": username,
                "password": password
            }
        )


        self.after(
            0,
            lambda:
                self.finish_login(
                    success,
                    response
                )
        )


    def finish_login(
        self,
        success,
        response
    ):

        if not success:

            self.login_button.config(
                text="SIGN IN",
                state="normal"
            )

            messagebox.showerror(
                "Login Failed",
                response.get(
                    "detail",
                    "Could not login."
                )
            )

            return


        self.token = response[
            "token"
        ]

        self.username = response[
            "username"
        ]


        self.save_session()


        self.show_activate_screen()


    # ========================================================
    # REGISTER
    # ========================================================

    def register(self):

        username = (
            self.username_entry
            .get()
            .strip()
        )

        password = (
            self.password_entry
            .get()
        )


        if not username or not password:

            messagebox.showwarning(
                "Register",
                "Enter a username and password."
            )

            return


        success, response = api_request(
            "/api/auth/register",
            method="POST",
            data={
                "username": username,
                "password": password
            }
        )


        if not success:

            messagebox.showerror(
                "Registration Failed",
                response.get(
                    "detail",
                    "Could not create account."
                )
            )

            return


        self.token = response[
            "token"
        ]

        self.username = response[
            "username"
        ]


        self.save_session()


        messagebox.showinfo(
            "Account Created",
            "Your account was created successfully."
        )


        self.show_activate_screen()


    # ========================================================
    # ACTIVATE LICENSE SCREEN
    # ========================================================

    def show_activate_screen(self):

        self.current_screen = "activate"

        self.clear_screen()

        self.title(
            "Resource Hub — Activate"
        )

        self.geometry(
            "760x590"
        )


        outer = tk.Frame(
            self,
            bg=BG
        )

        outer.pack(
            fill="both",
            expand=True,
            padx=80,
            pady=55
        )


        tk.Label(
            outer,
            text="WELCOME",
            bg=BG,
            fg=CYAN,
            font=("Segoe UI", 10, "bold")
        ).pack(
            anchor="w"
        )


        tk.Label(
            outer,
            text=self.username,
            bg=BG,
            fg=WHITE,
            font=("Segoe UI", 26, "bold")
        ).pack(
            anchor="w"
        )


        tk.Label(
            outer,
            text="Activate your license to continue.",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 10)
        ).pack(
            anchor="w",
            pady=(5, 28)
        )


        card = tk.Frame(
            outer,
            bg=CARD,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        card.pack(
            fill="x"
        )


        tk.Label(
            card,
            text="LICENSE KEY",
            bg=CARD,
            fg=TEXT,
            font=("Segoe UI", 9, "bold")
        ).pack(
            anchor="w",
            padx=28,
            pady=(25, 7)
        )


        self.activation_entry = tk.Entry(
            card,
            bg=INPUT,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=CYAN,
            font=("Consolas", 12)
        )

        self.activation_entry.pack(
            fill="x",
            padx=28,
            ipady=11
        )


        self.activation_entry.bind(
            "<Return>",
            lambda event:
                self.activate_license()
        )


        self.activate_license_button = (
            self.make_button(
                card,
                "ACTIVATE LICENSE",
                self.activate_license,
                CYAN,
                "#031019",
                padx=28,
                pady=11
            )
        )


        self.activate_license_button.pack(
            anchor="w",
            padx=28,
            pady=18
        )


        self.make_button(
            card,
            "LOG OUT",
            self.logout,
            "#32212b",
            "#f08ca5",
            padx=20,
            pady=9
        ).pack(
            anchor="w",
            padx=28,
            pady=(0, 25)
        )


    # ========================================================
    # ACTIVATE LICENSE
    # ========================================================

    def activate_license(self):

        key = (
            self.activation_entry
            .get()
            .strip()
            .upper()
        )


        if not key:

            messagebox.showwarning(
                "License",
                "Enter your license key."
            )

            return


        self.activate_license_button.config(
            text="CONNECTING...",
            state="disabled"
        )


        threading.Thread(
            target=self.activate_request,
            args=(key,),
            daemon=True
        ).start()


    def activate_request(self, key):

        success, response = api_request(
            "/api/license/activate",
            method="POST",
            data={
                "license_key": key,
                "hwid": self.hwid
            },
            token=self.token
        )


        self.after(
            0,
            lambda:
                self.finish_activation(
                    key,
                    success,
                    response
                )
        )


    def finish_activation(
        self,
        key,
        success,
        response
    ):

        if not success:

            self.activate_license_button.config(
                text="ACTIVATE LICENSE",
                state="normal"
            )

            messagebox.showerror(
                "Activation Failed",
                response.get(
                    "detail",
                    "Could not activate license."
                )
            )

            return


        self.license_key = key

        self.seconds_remaining = int(
            response.get(
                "seconds_remaining",
                0
            )
        )


        self.show_dashboard()


    # ========================================================
    # DASHBOARD
    # ========================================================

    def show_dashboard(self):

        self.current_screen = "dashboard"

        self.clear_screen()

        self.title(
            "Resource Hub"
        )

        self.geometry(
            "1400x820"
        )

        self.minsize(
            1100,
            650
        )


        # ====================================================
        # SIDEBAR
        # ====================================================

        sidebar = tk.Frame(
            self,
            bg=SIDEBAR,
            width=245
        )

        sidebar.pack(
            side="left",
            fill="y"
        )

        sidebar.pack_propagate(False)


        tk.Label(
            sidebar,
            text="RESOURCE HUB",
            bg=SIDEBAR,
            fg=WHITE,
            font=("Segoe UI", 17, "bold")
        ).pack(
            anchor="w",
            padx=25,
            pady=(30, 3)
        )


        tk.Label(
            sidebar,
            text="PRIVATE WORKSPACE",
            bg=SIDEBAR,
            fg=DIM,
            font=("Segoe UI", 8, "bold")
        ).pack(
            anchor="w",
            padx=27,
            pady=(0, 28)
        )


        self.sidebar_buttons = {}


        categories = [
            ("🔧", "Tools"),
            ("◉", "View Bots"),
            ("⚡", "Macros"),
            ("</>", "Scripts"),
            ("☷", "Tweaks"),
            ("▣", "Codes"),
            ("🎨", "Themes")
        ]


        for icon, name in categories:

            button = tk.Button(
                sidebar,
                text=f"{icon}    {name}",
                bg=(
                    "#0a1522"
                    if name == "Tools"
                    else SIDEBAR
                ),
                fg=(
                    CYAN
                    if name == "Tools"
                    else TEXT
                ),
                activebackground="#0e2132",
                activeforeground=CYAN,
                anchor="w",
                relief="flat",
                bd=0,
                cursor="hand2",
                font=(
                    "Segoe UI",
                    10,
                    "bold"
                    if name == "Tools"
                    else "normal"
                ),
                padx=25,
                pady=11,
                command=lambda n=name:
                    self.change_category(n)
            )


            button.pack(
                fill="x",
                padx=12,
                pady=2
            )


            self.sidebar_buttons[
                name
            ] = button


        tk.Frame(
            sidebar,
            bg=BORDER,
            height=1
        ).pack(
            fill="x",
            padx=20,
            pady=(25, 15)
        )


        tk.Label(
            sidebar,
            text="SECURITY",
            bg=SIDEBAR,
            fg=DIM,
            font=("Segoe UI", 8, "bold")
        ).pack(
            anchor="w",
            padx=27,
            pady=(0, 7)
        )


        for item in [
            "🎮    Cheats",
            "⬡    Spoofers",
            "🔑    Cracks"
        ]:

            tk.Label(
                sidebar,
                text=item + "     🔒",
                bg=SIDEBAR,
                fg="#52677a",
                anchor="w",
                font=("Segoe UI", 10),
                padx=25,
                pady=10
            ).pack(
                fill="x"
            )


        tk.Label(
            sidebar,
            text="v3.0",
            bg=SIDEBAR,
            fg=DIM,
            font=("Segoe UI", 8)
        ).pack(
            side="bottom",
            anchor="w",
            padx=27,
            pady=23
        )


        # ====================================================
        # MAIN
        # ====================================================

        main = tk.Frame(
            self,
            bg=BG
        )

        main.pack(
            side="left",
            fill="both",
            expand=True
        )


        # ====================================================
        # HEADER
        # ====================================================

        header = tk.Frame(
            main,
            bg=TOPBAR,
            height=88
        )

        header.pack(
            fill="x"
        )

        header.pack_propagate(False)


        search = tk.Frame(
            header,
            bg=INPUT,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        search.place(
            x=28,
            y=20,
            width=300,
            height=48
        )


        tk.Label(
            search,
            text="⌕",
            bg=INPUT,
            fg=MUTED,
            font=("Segoe UI", 17)
        ).pack(
            side="left",
            padx=(14, 5)
        )


        self.search_entry = tk.Entry(
            search,
            bg=INPUT,
            fg=MUTED,
            insertbackground=TEXT,
            relief="flat",
            bd=0,
            font=("Segoe UI", 10)
        )


        self.search_entry.insert(
            0,
            "Search tools..."
        )


        self.search_entry.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 12)
        )


        self.search_entry.bind(
            "<FocusIn>",
            self.search_focus_in
        )

        self.search_entry.bind(
            "<FocusOut>",
            self.search_focus_out
        )

        self.search_entry.bind(
            "<KeyRelease>",
            lambda event:
                self.filter_tools()
        )


        # USER

        tk.Label(
            header,
            text=self.username,
            bg=TOPBAR,
            fg=TEXT,
            font=("Segoe UI", 9, "bold")
        ).place(
            relx=1,
            x=-245,
            y=20,
            anchor="ne"
        )


        tk.Label(
            header,
            text="● PREMIUM",
            bg="#211d42",
            fg=PURPLE,
            font=("Segoe UI", 8, "bold"),
            padx=12,
            pady=7
        ).place(
            relx=1,
            x=-130,
            y=18,
            anchor="ne"
        )


        # TIME

        time_card = tk.Frame(
            header,
            bg="#0c1724",
            highlightbackground=PURPLE,
            highlightthickness=1
        )


        time_card.place(
            relx=1,
            x=-18,
            y=14,
            width=180,
            height=60,
            anchor="ne"
        )


        tk.Label(
            time_card,
            text="TIME LEFT",
            bg="#0c1724",
            fg=DIM,
            font=("Segoe UI", 7, "bold")
        ).pack(
            anchor="w",
            padx=13,
            pady=(7, 0)
        )


        self.time_label = tk.Label(
            time_card,
            text=format_time(
                self.seconds_remaining
            ),
            bg="#0c1724",
            fg=CYAN,
            font=("Segoe UI", 12, "bold")
        )


        self.time_label.pack(
            anchor="w",
            padx=13
        )


        # ====================================================
        # CONTENT
        # ====================================================

        self.content_canvas = tk.Canvas(
            main,
            bg=BG,
            highlightthickness=0
        )


        scrollbar = tk.Scrollbar(
            main,
            orient="vertical",
            command=self.content_canvas.yview
        )


        self.content_canvas.configure(
            yscrollcommand=scrollbar.set
        )


        self.content_canvas.pack(
            side="left",
            fill="both",
            expand=True
        )


        scrollbar.pack(
            side="right",
            fill="y"
        )


        self.dashboard_content = tk.Frame(
            self.content_canvas,
            bg=BG
        )


        self.dashboard_window = (
            self.content_canvas.create_window(
                (0, 0),
                window=self.dashboard_content,
                anchor="nw"
            )
        )


        self.dashboard_content.bind(
            "<Configure>",
            lambda event:
                self.content_canvas.configure(
                    scrollregion=
                    self.content_canvas.bbox(
                        "all"
                    )
                )
        )


        self.content_canvas.bind(
            "<Configure>",
            lambda event:
                self.content_canvas.itemconfigure(
                    self.dashboard_window,
                    width=event.width
                )
        )


        self.content_canvas.bind_all(
            "<MouseWheel>",
            self.dashboard_mousewheel
        )


        self.build_dashboard_content()


        # IMPORTANT:
        # Make sure the time label is populated
        # immediately instead of waiting for an update.

        self.time_label.config(
            text=format_time(
                self.seconds_remaining
            )
        )


        self.after(
            1000,
            self.update_countdown
        )


        self.after(
            30000,
            self.validate_current_license
        )


    # ========================================================
    # DASHBOARD CONTENT
    # ========================================================

    def build_dashboard_content(self):

        for widget in (
            self.dashboard_content
            .winfo_children()
        ):

            widget.destroy()


        container = tk.Frame(
            self.dashboard_content,
            bg=BG
        )


        container.pack(
            fill="both",
            expand=True,
            padx=35,
            pady=30
        )


        tk.Label(
            container,
            text=self.selected_category,
            bg=BG,
            fg=WHITE,
            font=("Segoe UI", 24, "bold")
        ).pack(
            anchor="w"
        )


        descriptions = {

            "Tools":
                "General utilities and workspace tools.",

            "View Bots":
                "Bot utilities and viewing tools.",

            "Macros":
                "Automation and macro utilities.",

            "Scripts":
                "Script workspace and utilities.",

            "Tweaks":
                "Configuration and customization tools.",

            "Codes":
                "Code utilities and snippets.",

            "Themes":
                "Appearance and customization."
        }


        tk.Label(
            container,
            text=descriptions.get(
                self.selected_category,
                ""
            ),
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 9)
        ).pack(
            anchor="w",
            pady=(4, 22)
        )


        grid = tk.Frame(
            container,
            bg=BG
        )


        grid.pack(
            fill="both",
            expand=True
        )


        tools = self.get_tools(
            self.selected_category
        )


        self.tool_cards = []


        for column in range(3):

            grid.columnconfigure(
                column,
                weight=1
            )


        for row in range(2):

            grid.rowconfigure(
                row,
                weight=1
            )


        for index, tool in enumerate(
            tools
        ):

            row = index // 3
            column = index % 3


            card = tk.Frame(
                grid,
                bg=CARD,
                highlightbackground=BORDER,
                highlightthickness=1
            )


            card.grid(
                row=row,
                column=column,
                sticky="nsew",
                padx=8,
                pady=8
            )


            tk.Label(
                card,
                text=tool["icon"],
                bg=CARD,
                fg=tool["accent"],
                font=("Segoe UI", 25, "bold")
            ).pack(
                anchor="w",
                padx=18,
                pady=(22, 10)
            )


            tk.Label(
                card,
                text=tool["name"],
                bg=CARD,
                fg=WHITE,
                font=("Segoe UI", 12, "bold")
            ).pack(
                anchor="w",
                padx=18
            )


            tk.Label(
                card,
                text=tool["description"],
                bg=CARD,
                fg=MUTED,
                wraplength=230,
                justify="left",
                font=("Segoe UI", 9)
            ).pack(
                anchor="w",
                padx=18,
                pady=(6, 18)
            )


            tk.Button(
                card,
                text="OPEN TOOL",
                command=lambda name=tool["name"]:
                    self.open_tool(name),
                bg="#0b1928",
                fg=CYAN,
                activebackground="#10283b",
                activeforeground=WHITE,
                relief="flat",
                cursor="hand2",
                font=("Segoe UI", 9, "bold"),
                padx=20,
                pady=8
            ).pack(
                anchor="w",
                padx=18,
                pady=(0, 22)
            )


            self.tool_cards.append(
                {
                    "card": card,
                    "name":
                        tool["name"].lower(),
                    "description":
                        tool["description"].lower()
                }
            )


    def get_tools(self, category):

        data = {

            "Tools": [

                {
                    "icon": "◉",
                    "name": "Discord Mass DM",
                    "description":
                        "Bulk messaging automation",
                    "accent": CYAN
                },

                {
                    "icon": "◈",
                    "name": "Twitch Viewer Bot",
                    "description":
                        "Viewer count booster",
                    "accent": PURPLE
                },

                {
                    "icon": "⚡",
                    "name": "Auto Clicker Pro",
                    "description":
                        "Customizable macro clicks",
                    "accent": CYAN
                },

                {
                    "icon": "◌",
                    "name": "Proxy Scraper",
                    "description":
                        "Fresh proxy generator",
                    "accent": BLUE
                },

                {
                    "icon": "✓",
                    "name": "Account Checker",
                    "description":
                        "Multi-service validator",
                    "accent": PURPLE
                },

                {
                    "icon": "🎨",
                    "name": "Theme Editor",
                    "description":
                        "Custom appearance editor",
                    "accent": CYAN
                }
            ],

            "View Bots": [

                {
                    "icon": "◉",
                    "name": "Bot Monitor",
                    "description":
                        "View active bot sessions",
                    "accent": CYAN
                },

                {
                    "icon": "◌",
                    "name": "Session Viewer",
                    "description":
                        "Inspect workspace sessions",
                    "accent": PURPLE
                },

                {
                    "icon": "◎",
                    "name": "Status Monitor",
                    "description":
                        "Monitor workspace status",
                    "accent": BLUE
                }
            ],

            "Macros": [

                {
                    "icon": "⚡",
                    "name": "Macro Builder",
                    "description":
                        "Create macro sequences",
                    "accent": CYAN
                },

                {
                    "icon": "●",
                    "name": "Macro Recorder",
                    "description":
                        "Record reusable actions",
                    "accent": PURPLE
                },

                {
                    "icon": "▶",
                    "name": "Macro Runner",
                    "description":
                        "Run saved macro profiles",
                    "accent": BLUE
                }
            ],

            "Scripts": [

                {
                    "icon": "</>",
                    "name": "Script Manager",
                    "description":
                        "Organize local scripts",
                    "accent": CYAN
                },

                {
                    "icon": "⌁",
                    "name": "Script Runner",
                    "description":
                        "Run configured scripts",
                    "accent": PURPLE
                },

                {
                    "icon": "▣",
                    "name": "Script Library",
                    "description":
                        "Browse available scripts",
                    "accent": BLUE
                }
            ],

            "Tweaks": [

                {
                    "icon": "☷",
                    "name": "Performance",
                    "description":
                        "Performance settings",
                    "accent": CYAN
                },

                {
                    "icon": "◈",
                    "name": "Interface",
                    "description":
                        "Interface configuration",
                    "accent": PURPLE
                },

                {
                    "icon": "⚙",
                    "name": "Settings",
                    "description":
                        "Application settings",
                    "accent": BLUE
                }
            ],

            "Codes": [

                {
                    "icon": "</>",
                    "name": "Code Viewer",
                    "description":
                        "View workspace code",
                    "accent": CYAN
                },

                {
                    "icon": "▣",
                    "name": "Snippet Library",
                    "description":
                        "Reusable code snippets",
                    "accent": PURPLE
                },

                {
                    "icon": "✓",
                    "name": "Validator",
                    "description":
                        "Validate snippets",
                    "accent": BLUE
                }
            ],

            "Themes": [

                {
                    "icon": "🎨",
                    "name": "Theme Editor",
                    "description":
                        "Customize appearance",
                    "accent": CYAN
                },

                {
                    "icon": "◈",
                    "name": "Ocean",
                    "description":
                        "Deep ocean interface",
                    "accent": BLUE
                },

                {
                    "icon": "✦",
                    "name": "Purple Night",
                    "description":
                        "Dark purple interface",
                    "accent": PURPLE
                }
            ]
        }


        return data.get(
            category,
            data["Tools"]
        )


    # ========================================================
    # SIDEBAR
    # ========================================================

    def change_category(self, category):

        self.selected_category = category


        for name, button in (
            self.sidebar_buttons.items()
        ):

            if name == category:

                button.config(
                    bg="#0a1522",
                    fg=CYAN
                )

            else:

                button.config(
                    bg=SIDEBAR,
                    fg=TEXT
                )


        self.build_dashboard_content()


    # ========================================================
    # SEARCH
    # ========================================================

    def search_focus_in(self, event):

        if (
            self.search_entry.get()
            == "Search tools..."
        ):

            self.search_entry.delete(
                0,
                tk.END
            )

            self.search_entry.config(
                fg=TEXT
            )


    def search_focus_out(self, event):

        if not self.search_entry.get().strip():

            self.search_entry.insert(
                0,
                "Search tools..."
            )

            self.search_entry.config(
                fg=MUTED
            )


    def filter_tools(self):

        if not self.tool_cards:
            return


        query = (
            self.search_entry
            .get()
            .strip()
            .lower()
        )


        if query == "search tools...":

            query = ""


        for item in self.tool_cards:

            matches = (
                query in item["name"]
                or
                query in item["description"]
            )


            if matches:

                item["card"].grid()

            else:

                item["card"].grid_remove()


    # ========================================================
    # MOUSE WHEEL
    # ========================================================

    def dashboard_mousewheel(
        self,
        event
    ):

        if self.current_screen != "dashboard":
            return

        self.content_canvas.yview_scroll(
            int(-event.delta / 120),
            "units"
        )


    # ========================================================
    # OPEN TOOL
    # ========================================================

    def open_tool(self, name):

        messagebox.showinfo(
            name,
            (
                f"{name}\n\n"
                "The dashboard interface is ready. "
                "This tool has not been connected yet."
            )
        )


    # ========================================================
    # COUNTDOWN
    # ========================================================

    def update_countdown(self):

        if self.current_screen != "dashboard":

            return


        if self.seconds_remaining <= 0:

            self.expire_license()

            return


        self.time_label.config(
            text=format_time(
                self.seconds_remaining
            )
        )


        self.seconds_remaining -= 1


        self.after(
            1000,
            self.update_countdown
        )


    # ========================================================
    # SERVER VALIDATION
    # ========================================================

    def validate_current_license(self):

        if self.current_screen != "dashboard":

            return


        success, response = api_request(
            "/api/license/validate",
            method="POST",
            data={
                "license_key":
                    self.license_key,
                "hwid":
                    self.hwid
            },
            token=self.token
        )


        if not success:

            self.remove_session()

            messagebox.showerror(
                "License Validation",
                response.get(
                    "detail",
                    "License validation failed."
                )
            )

            self.show_login()

            return


        self.seconds_remaining = int(
            response.get(
                "seconds_remaining",
                0
            )
        )


        self.after(
            30000,
            self.validate_current_license
        )


    # ========================================================
    # EXPIRE
    # ========================================================

    def expire_license(self):

        self.remove_session()

        messagebox.showwarning(
            "License Expired",
            (
                "Your license has expired.\n\n"
                "You have been logged out."
            )
        )

        self.token = ""
        self.username = ""
        self.license_key = ""
        self.seconds_remaining = 0

        self.show_login()


    # ========================================================
    # LOGOUT
    # ========================================================

    def logout(self):

        if self.token:

            api_request(
                "/api/auth/logout",
                method="POST",
                token=self.token,
                timeout=5
            )


        self.remove_session()

        self.token = ""
        self.username = ""
        self.license_key = ""
        self.seconds_remaining = 0

        self.show_login()


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    app = ResourceHub()

    app.mainloop()
