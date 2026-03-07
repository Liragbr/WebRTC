import tkinter as tk
from tkinter import ttk, scrolledtext
import subprocess
import threading
from collections import Counter
import re
import urllib.request
import json

class WebRTCAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("WebRTC STUN IP Analyzer")
        self.root.geometry("900x600")
        self.root.configure(bg="#0d1117")
        self.root.minsize(850, 550)

        self.process = None
        self.running = False
        self.ip_counter = Counter()
        self.geo_cache = {}

        self.configure_style()
        self.build_ui()

    def configure_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TFrame", background="#0d1117")
        style.configure("TLabel", background="#0d1117", foreground="#c9d1d9", font=("Segoe UI", 10))
        style.configure("TEntry",
                        fieldbackground="#161b22",
                        background="#161b22",
                        foreground="#ffffff",
                        bordercolor="#30363d",
                        lightcolor="#30363d",
                        darkcolor="#30363d",
                        padding=6)

        style.configure("TButton",
                        background="#21262d",
                        foreground="#ffffff",
                        padding=6,
                        borderwidth=0)

        style.map("TButton",
                  background=[("active", "#30363d")])

    def build_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        title = tk.Label(main_frame,
                         text="WebRTC STUN IP Analyzer",
                         font=("Segoe UI Semibold", 16),
                         bg="#0d1117",
                         fg="#58a6ff")
        title.pack(anchor="w", pady=(0, 15))

        config_frame = ttk.Frame(main_frame)
        config_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(config_frame, text="Interface de Rede:").grid(row=0, column=0, sticky="w", pady=5)
        self.interface_entry = ttk.Entry(config_frame, width=30)
        self.interface_entry.grid(row=0, column=1, sticky="w", padx=(10, 0))

        ttk.Label(config_frame, text="Seu IP Público:").grid(row=1, column=0, sticky="w", pady=5)

        ip_frame = ttk.Frame(config_frame)
        ip_frame.grid(row=1, column=1, sticky="w", padx=(10, 0))

        self.public_ip_entry = ttk.Entry(ip_frame, width=18)
        self.public_ip_entry.pack(side=tk.LEFT, padx=(0, 8))

        self.get_ip_btn = ttk.Button(ip_frame, text="Descobrir", command=self.fetch_public_ip)
        self.get_ip_btn.pack(side=tk.LEFT)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=10)

        self.start_btn = ttk.Button(btn_frame, text="Iniciar Captura", command=self.start)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.stop_btn = ttk.Button(btn_frame, text="Parar Captura", command=self.stop)
        self.stop_btn.pack(side=tk.LEFT)

        self.output = scrolledtext.ScrolledText(
            main_frame,
            bg="#161b22",
            fg="#c9d1d9",
            insertbackground="#ffffff",
            font=("Consolas", 10),
            relief="flat",
            borderwidth=0
        )
        self.output.pack(fill="both", expand=True, pady=(15, 0))

    def fetch_public_ip(self):
        self.get_ip_btn.config(text="Buscando...", state=tk.DISABLED)
        threading.Thread(target=self._fetch_ip_thread, daemon=True).start()

    def _fetch_ip_thread(self):
        try:
            req = urllib.request.Request("https://api.ipify.org",
                                         headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                ip = response.read().decode('utf-8').strip()
            self.root.after(0, self._update_ip_entry, ip)
        except Exception as e:
            self.root.after(0, self._update_ip_entry, "")
            self.root.after(0, lambda: self.log(f"[ERRO] Falha ao buscar IP: {e}"))

    def _update_ip_entry(self, ip):
        if ip:
            self.public_ip_entry.delete(0, tk.END)
            self.public_ip_entry.insert(0, ip)
        self.get_ip_btn.config(text="Descobrir", state=tk.NORMAL)

    def get_geo_info(self, ip):
        if ip in self.geo_cache:
            return self.geo_cache[ip]

        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp"
            req = urllib.request.Request(url,
                                         headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=3) as response:
                data = json.loads(response.read().decode())

            if data.get("status") == "success":
                geo_info = f"{data.get('city', 'N/A')}, {data.get('country', 'N/A')} | ISP: {data.get('isp', 'N/A')}"
            else:
                geo_info = "Falha ao localizar"

            self.geo_cache[ip] = geo_info
            return geo_info
        except Exception:
            return "Erro na busca de localização"

    def log(self, message):
        self.output.insert(tk.END, message + "\n")
        self.output.see(tk.END)

    def start(self):
        interface = self.interface_entry.get().strip()
        public_ip = self.public_ip_entry.get().strip()

        if not interface:
            self.log("[ERRO] Informe a interface de rede (ex: Wi-Fi, eth0).")
            return

        self.running = True
        self.ip_counter.clear()
        self.output.delete(1.0, tk.END)

        if not public_ip:
            display_filter = "stun.type == 0x0101 && stun.att.type == 0x0020"
            self.log("[INFO] IP público não informado. Sem exclusão de origem.")
        else:
            display_filter = f"stun.type == 0x0101 && stun.att.type == 0x0020 && stun.att.ipv4 != {public_ip}"
            self.log(f"[INFO] IP público {public_ip} será excluído.")

        self.log(f"[INFO] Iniciando captura STUN na interface '{interface}'...\n")

        command = [
            r"C:\Program Files\Wireshark\tshark.exe",
            "-l", 
            "-i", interface,
            "-f", "udp",
            "-Y", display_filter,
            "-T", "fields",
            "-e", "stun.att.ipv4"
        ]

        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            threading.Thread(target=self.read_output, daemon=True).start()
        except Exception as e:
            self.log(f"[ERRO] Falha ao iniciar TShark: {e}")

    def read_output(self):
        ip_regex = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

        while self.running and self.process:
            line = self.process.stdout.readline().strip()

            if not line and self.process.poll() is not None:
                break

            if line:
                for ip in line.split(','):
                    ip = ip.strip()
                    if ip_regex.match(ip):
                        self.ip_counter[ip] += 1
                        self.root.after(0, self.analyze)

    def analyze(self):
        total_packets = sum(self.ip_counter.values())

        self.output.delete(1.0, tk.END)
        self.log("=== Análise STUN ===")
        self.log(f"Pacotes capturados: {total_packets}\n")

        if self.ip_counter:
            self.log("IPs Detectados:")
            for ip, count in self.ip_counter.most_common():
                geo_data = self.get_geo_info(ip)
                self.log(f"  {ip} | {count} pacotes | {geo_data}")
        else:
            self.log("Aguardando negociação de conexão...")

    def stop(self):
        self.running = False
        if self.process:
            self.process.terminate()
            self.process = None
        self.log("[INFO] Captura encerrada.")

if __name__ == "__main__":
    root = tk.Tk()
    app = WebRTCAnalyzer(root)
    root.mainloop()