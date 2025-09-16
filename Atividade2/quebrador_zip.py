import pyzipper
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import os
import tempfile


class AESZipAttacker:
    """Classe responsável por realizar o ataque de dicionário em arquivos ZIP AES."""

    def __init__(self, zip_file, wordlists):
        self.zip_file = zip_file
        self.wordlists = wordlists

    def _passwords(self):
        """Gerador de senhas a partir das wordlists."""
        for dic in self.wordlists:
            try:
                with open(dic, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        pwd = line.strip()
                        if pwd:
                            yield pwd
            except Exception as e:
                print(f"[!] Erro ao abrir dicionário {dic}: {e}")
        # fallback básico
        if not self.wordlists:
            for pwd in ["123", "admin", "senha"]:
                yield pwd

    def run(self, on_progress=None, on_try=None):
        """Executa o ataque, chamando callbacks para progresso e senha atual."""
        candidates = list(self._passwords())
        total = len(candidates)

        for idx, password in enumerate(candidates, 1):
            pwd_bytes = password.encode("utf-8")

            if on_try:
                on_try(password)

            try:
                with pyzipper.AESZipFile(self.zip_file) as zf:
                    with tempfile.TemporaryDirectory() as tmpdir:
                        zf.extractall(path=tmpdir, pwd=pwd_bytes)
                        return password  # sucesso
            except RuntimeError:
                pass  # senha incorreta
            except Exception as e:
                print(f"[!] Problema ao tentar '{password}': {e}")

            if on_progress:
                on_progress(idx, total)

        return None


class QuebradorDeSenha:
    """Interface gráfica para uso do AESZipAttacker."""

    def __init__(self, master):
        self.master = master
        self.master.title("Quebrador de ZIP AES")

        self.zip_path = tk.StringVar()
        self.wordlists = []

        # Seção do ZIP
        tk.Label(master, text="Selecione o arquivo ZIP:").pack(pady=(10, 0))
        tk.Entry(master, textvariable=self.zip_path, width=50).pack()
        tk.Button(master, text="Escolher ZIP", command=self.pick_zip).pack(pady=5)

        # Seção dos dicionários
        frame_dic = tk.Frame(master)
        frame_dic.pack(pady=10)
        tk.Button(frame_dic, text="Adicionar Dicionário", command=self.add_dic).grid(row=0, column=0, padx=5)
        tk.Button(frame_dic, text="Remover Selecionado", command=self.remove_dic).grid(row=0, column=1, padx=5)

        self.dic_listbox = tk.Listbox(master, width=50, height=5)
        self.dic_listbox.pack()

        # Barra de progresso
        self.progress = ttk.Progressbar(master, orient="horizontal", length=400, mode="determinate")
        self.progress.pack(pady=10)

        # Senha atual
        self.current_var = tk.StringVar(value="Senha em teste: -")
        tk.Label(master, textvariable=self.current_var).pack()

        # Botão iniciar
        tk.Button(master, text="Iniciar ataque", command=self.start_attack).pack(pady=15)

    def pick_zip(self):
        path = filedialog.askopenfilename(filetypes=[("Arquivos ZIP", "*.zip")])
        if path:
            self.zip_path.set(path)

    def add_dic(self):
        path = filedialog.askopenfilename(filetypes=[("Arquivos TXT", "*.txt")])
        if path:
            self.wordlists.append(path)
            self.dic_listbox.insert(tk.END, os.path.basename(path))

    def remove_dic(self):
        sel = self.dic_listbox.curselection()
        for i in reversed(sel):
            self.dic_listbox.delete(i)
            del self.wordlists[i]

    def start_attack(self):
        if not self.zip_path.get():
            messagebox.showerror("Erro", "Selecione um arquivo ZIP.")
            return

        def update_progress(done, total):
            self.progress["value"] = (done / total) * 100
            self.master.update_idletasks()

        def update_current(pwd):
            self.current_var.set(f"Senha em teste: {pwd}")
            self.master.update_idletasks()

        def task():
            attacker = AESZipAttacker(self.zip_path.get(), self.wordlists)
            result = attacker.run(on_progress=update_progress, on_try=update_current)
            if result:
                messagebox.showinfo("Sucesso", f"Senha encontrada: {result}")
            else:
                messagebox.showwarning("Falhou", "Nenhuma senha da lista funcionou.")
            self.progress["value"] = 0
            self.current_var.set("Senha em teste: -")

        threading.Thread(target=task, daemon=True).start()


def main():
    root = tk.Tk()
    app = QuebradorDeSenha(root)
    root.mainloop()


if __name__ == "__main__":
    main()
