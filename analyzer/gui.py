import http.client
import multiprocessing
import queue
import threading
import time
import tkinter as tk
from tkinter import ttk

from .capture import command, run
from .enrichment import assess, baseline, geo, public_ip


def lookup(pipe, address):
    try:
        value = public_ip() if address is None else geo(address)
        pipe.send((True, value))
    except (ValueError, OSError, http.client.HTTPException) as exc:
        pipe.send((False, str(exc)))
    finally:
        pipe.close()


class Analyzer:
    def __init__(self, root):
        self.root = root
        root.title("WebRTC · Observações STUN")
        frame = ttk.Frame(root, padding=16)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(6, weight=1)
        self.interface = self.field(frame, 0, "Interface (índice de tshark -D)")
        self.local = self.field(frame, 1, "IP local de destino das respostas")
        self.expected = self.field(frame, 2, "Saídas previstas (IPs separados por vírgula)")
        ttk.Button(frame, text="Consultar minha saída HTTPS (ipify)", command=self.discover).grid(
            row=3, column=1
        )
        buttons = ttk.Frame(frame)
        buttons.grid(row=4, columnspan=2, pady=8)
        for label, action in [
            ("Iniciar", self.start),
            ("Parar", self.stop_capture),
            ("Consultar IP selecionado (ipinfo.io)", self.locate),
        ]:
            ttk.Button(buttons, text=label, command=action).pack(side="left", padx=3)
        self.status = tk.StringVar(value="Pronto")
        ttk.Label(frame, textvariable=self.status, wraplength=720).grid(
            row=5, columnspan=2, sticky="w"
        )
        self.table = ttk.Treeview(
            frame, columns=("IP", "Porta", "Transação", "Avaliação"), show="headings"
        )
        for col in self.table["columns"]:
            self.table.heading(col, text=col)
        self.table.grid(row=6, columnspan=2, sticky="nsew")
        self.worker = self.http = None
        self.closing = False
        self.events = queue.Queue(256)
        self.cancel = threading.Event()
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(100, self.tick)

    @staticmethod
    def field(parent, row, text):
        ttk.Label(parent, text=text).grid(row=row, column=0, sticky="w")
        value = tk.StringVar()
        ttk.Entry(parent, textvariable=value).grid(row=row, column=1, sticky="ew")
        return value

    def start(self):
        if self.worker or self.closing:
            return
        try:
            args = command(self.local.get().strip(), interface=self.interface.get().strip())
            expected = baseline(self.expected.get())
        except (OSError, ValueError) as exc:
            self.status.set(str(exc))
            return
        self.table.delete(*self.table.get_children())
        self.cancel.clear()
        self.status.set("Captura em execução (até 120 s)")

        def capture():
            dropped = 0

            def observe(mapping):
                nonlocal dropped
                try:
                    self.events.put_nowait((mapping, assess(mapping.address, expected)))
                except queue.Full:
                    dropped += 1

            try:
                run(args, self.cancel, observe)
                self.result = f"Encerrada. Observações descartadas por fila cheia: {dropped}"
            except (OSError, ValueError, RuntimeError) as exc:
                self.result = str(exc)

        self.worker = threading.Thread(target=capture)
        self.worker.start()

    def stop_capture(self):
        self.cancel.set()

    def discover(self):
        self.start_lookup(None)

    def locate(self):
        selected = self.table.selection()
        if selected:
            self.start_lookup(self.table.set(selected[0], "IP"))

    def start_lookup(self, address):
        if self.http or self.closing:
            return
        ctx = multiprocessing.get_context("spawn")
        reader, writer = ctx.Pipe(duplex=False)
        process = ctx.Process(target=lookup, args=(writer, address))
        try:
            process.start()
        except OSError as exc:
            reader.close()
            self.status.set(str(exc))
            return
        finally:
            writer.close()
        self.http = process, reader, address, time.monotonic() + 8
        self.status.set("Consulta HTTPS em andamento")

    def poll_lookup(self):
        process, pipe, address, deadline = self.http
        if process.is_alive() and not self.closing and time.monotonic() < deadline:
            return
        if process.is_alive():
            process.kill()
        process.join()
        try:
            ok, value = pipe.recv()
            if ok and address is None:
                self.expected.set(value)
            self.status.set(value)
        except EOFError:
            self.status.set("Consulta interrompida ou expirada")
        finally:
            pipe.close()
            process.close()
            self.http = None

    def tick(self):
        if self.http:
            self.poll_lookup()
        for _ in range(256):
            try:
                mapping, verdict = self.events.get_nowait()
            except queue.Empty:
                break
            self.table.insert(
                "", "end", values=(str(mapping.address), mapping.port, mapping.transaction, verdict)
            )
        rows = self.table.get_children()
        if len(rows) > 500:
            self.table.delete(*rows[:-500])
        if self.worker and not self.worker.is_alive() and self.events.empty():
            self.worker.join()
            self.worker = None
            self.status.set(self.result)
        if self.closing and not self.worker and not self.http:
            self.root.destroy()
        else:
            self.root.after(100, self.tick)

    def close(self):
        self.closing = True
        self.stop_capture()


def main():
    root = tk.Tk()
    Analyzer(root)
    root.mainloop()
