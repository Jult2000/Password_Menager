import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import base64
import secrets
import string
import os
import hashlib

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager Pro")
        self.root.geometry("900x600")
        
        self.admin_password = "%tua_password%"
        self.master_password = None
        self.passwords = []
        self.vault_file = "passwords.vault"
        self.is_admin_logged = False
        self.is_unlocked = False
        
        self.create_admin_login_screen()
    
    def xor_encrypt_decrypt(self, data, key):
        """Cripta/Decripta con XOR"""
        key_bytes = key.encode()
        data_bytes = data.encode() if isinstance(data, str) else data
        result = bytearray()
        for i, byte in enumerate(data_bytes):
            result.append(byte ^ key_bytes[i % len(key_bytes)])
        return bytes(result)
    
    def create_admin_login_screen(self):
        """Schermata di login amministratore"""
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="50")
        frame.pack(expand=True)
        
        ttk.Label(frame, text="🔐 PASSWORD MANAGER PRO", font=('Arial', 24, 'bold')).pack(pady=30)
        ttk.Label(frame, text="Accesso Amministratore", font=('Arial', 12)).pack(pady=10)
        
        ttk.Label(frame, text="Password Admin:").pack(pady=5)
        self.admin_entry = ttk.Entry(frame, show="●", width=30, font=('Arial', 12))
        self.admin_entry.pack(pady=5)
        self.admin_entry.bind('<Return>', lambda e: self.check_admin_login())
        
        ttk.Button(frame, text="Accedi", command=self.check_admin_login, width=20).pack(pady=20)
        
        self.admin_entry.focus()
    
    def check_admin_login(self):
        """Verifica password admin"""
        if self.admin_entry.get() == self.admin_password:
            self.is_admin_logged = True
            self.create_vault_menu()
        else:
            messagebox.showerror("Errore", "Password amministratore errata!")
            self.admin_entry.delete(0, tk.END)
    
    def create_vault_menu(self):
        """Menu principale dopo login admin"""
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="50")
        frame.pack(expand=True)
        
        ttk.Label(frame, text="VAULT MANAGER", font=('Arial', 20, 'bold')).pack(pady=20)
        
        ttk.Label(frame, text="Password Vault:").pack(pady=5)
        self.master_entry = ttk.Entry(frame, show="●", width=30, font=('Arial', 11))
        self.master_entry.pack(pady=5)
        self.master_entry.bind('<Return>', lambda e: self.unlock_vault())
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="Apri Vault", command=self.unlock_vault, width=15).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(btn_frame, text="Crea Nuovo Vault", command=self.create_new_vault, width=15).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(btn_frame, text="Carica File Vault", command=self.load_vault_file, width=15).grid(row=1, column=0, padx=5, pady=5)
        ttk.Button(btn_frame, text="Esci", command=self.logout_admin, width=15).grid(row=1, column=1, padx=5, pady=5)
        
        self.master_entry.focus()
    
    def logout_admin(self):
        """Logout amministratore"""
        self.is_admin_logged = False
        self.is_unlocked = False
        self.passwords = []
        self.create_admin_login_screen()
    
    def create_new_vault(self):
        """Crea un nuovo vault"""
        password = self.master_entry.get()
        if len(password) < 4:
            messagebox.showerror("Errore", "La password deve avere almeno 4 caratteri")
            return
        
        self.master_password = password
        self.passwords = []
        self.is_unlocked = True
        self.save_vault()
        messagebox.showinfo("Successo", "Nuovo vault creato!")
        self.create_main_screen()
    
    def unlock_vault(self):
        """Sblocca il vault esistente"""
        password = self.master_entry.get()
        if len(password) < 4:
            messagebox.showerror("Errore", "Password troppo corta")
            return
        
        if not os.path.exists(self.vault_file):
            messagebox.showerror("Errore", "Nessun vault trovato. Crea un nuovo vault.")
            return
        
        try:
            with open(self.vault_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.xor_encrypt_decrypt(encrypted_data, password)
            self.passwords = json.loads(decrypted_data.decode())
            
            self.master_password = password
            self.is_unlocked = True
            messagebox.showinfo("Successo", "Vault sbloccato!")
            self.create_main_screen()
        except Exception as e:
            messagebox.showerror("Errore", f"Password errata o file corrotto!\n{str(e)}")
    
    def load_vault_file(self):
        """Carica un file vault personalizzato"""
        filename = filedialog.askopenfilename(
            title="Seleziona file vault",
            filetypes=[("Vault files", "*.vault"), ("All files", "*.*")]
        )
        if filename:
            self.vault_file = filename
            messagebox.showinfo("Info", f"Vault caricato: {os.path.basename(filename)}")
    
    def save_vault(self):
        """Salva il vault criptato"""
        if not self.master_password:
            return
        
        data = json.dumps(self.passwords, indent=2)
        encrypted_data = self.xor_encrypt_decrypt(data, self.master_password)
        
        with open(self.vault_file, 'wb') as f:
            f.write(encrypted_data)
    
    def clear_window(self):
        """Pulisce la finestra"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def create_main_screen(self):
        """Schermata principale con lista password"""
        self.clear_window()
        
        # Header
        header = ttk.Frame(self.root, padding="10")
        header.pack(fill=tk.X)
        
        ttk.Label(header, text="🔐 GESTIONE PASSWORD", font=('Arial', 16, 'bold')).pack(side=tk.LEFT)
        ttk.Button(header, text="🔒 Blocca", command=self.lock_vault).pack(side=tk.RIGHT, padx=5)
        ttk.Label(header, text=f"Password salvate: {len(self.passwords)}", font=('Arial', 10)).pack(side=tk.RIGHT, padx=20)
        
        # Toolbar
        toolbar = ttk.Frame(self.root, padding="10")
        toolbar.pack(fill=tk.X)
        
        ttk.Button(toolbar, text="➕ Crea Nuova Password", command=self.add_password_window, width=25).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="✏️ Modifica", command=self.edit_password, width=12).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="🗑️ Elimina", command=self.delete_password, width=12).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="📋 Copia Pass", command=self.copy_password, width=12).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="👁️ Mostra", command=self.toggle_password_visibility, width=12).pack(side=tk.LEFT, padx=5)
        
        # Toolbar 2
        toolbar2 = ttk.Frame(self.root, padding="10")
        toolbar2.pack(fill=tk.X)
        
        ttk.Button(toolbar2, text="💾 Esporta Vault", command=self.export_vault, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar2, text="📥 Importa Vault", command=self.import_vault, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar2, text="🔍 Cerca", command=self.search_window, width=15).pack(side=tk.LEFT, padx=5)
        
        # Barra di ricerca
        search_frame = ttk.Frame(self.root, padding="10")
        search_frame.pack(fill=tk.X)
        
        ttk.Label(search_frame, text="Ricerca rapida:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_passwords)
        ttk.Entry(search_frame, textvariable=self.search_var, width=40).pack(side=tk.LEFT, padx=10)
        
        # Lista password
        list_frame = ttk.Frame(self.root)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Scrollbar
        scrollbar_y = ttk.Scrollbar(list_frame, orient=tk.VERTICAL)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        
        scrollbar_x = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Treeview
        columns = ('Sito', 'Username', 'Password', 'Note', 'Data')
        self.tree = ttk.Treeview(
            list_frame, 
            columns=columns, 
            show='headings', 
            yscrollcommand=scrollbar_y.set,
            xscrollcommand=scrollbar_x.set
        )
        scrollbar_y.config(command=self.tree.yview)
        scrollbar_x.config(command=self.tree.xview)
        
        self.tree.heading('Sito', text='Sito/Applicazione')
        self.tree.heading('Username', text='Username/Email')
        self.tree.heading('Password', text='Password')
        self.tree.heading('Note', text='Note')
        self.tree.heading('Data', text='Data creazione')
        
        self.tree.column('Sito', width=180)
        self.tree.column('Username', width=200)
        self.tree.column('Password', width=150)
        self.tree.column('Note', width=180)
        self.tree.column('Data', width=140)
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Double click per mostrare dettagli
        self.tree.bind('<Double-1>', lambda e: self.show_password_details())
        
        self.password_visible = {}
        self.refresh_list()
    
    def refresh_list(self):
        """Aggiorna la lista delle password"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for i, pwd in enumerate(self.passwords):
            password_display = self.password_visible.get(i, False) and pwd['password'] or '●' * 10
            self.tree.insert('', tk.END, values=(
                pwd['site'],
                pwd['username'],
                password_display,
                pwd.get('note', '')[:50],
                pwd.get('created', 'N/A')
            ), iid=i)
    
    def filter_passwords(self, *args):
        """Filtra le password in base alla ricerca"""
        search_term = self.search_var.get().lower()
        
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for i, pwd in enumerate(self.passwords):
            if (search_term in pwd['site'].lower() or 
                search_term in pwd['username'].lower() or 
                search_term in pwd.get('note', '').lower()):
                
                password_display = self.password_visible.get(i, False) and pwd['password'] or '●' * 10
                self.tree.insert('', tk.END, values=(
                    pwd['site'],
                    pwd['username'],
                    password_display,
                    pwd.get('note', '')[:50],
                    pwd.get('created', 'N/A')
                ), iid=i)
    
    def add_password_window(self):
        """Finestra per aggiungere password"""
        win = tk.Toplevel(self.root)
        win.title("➕ Crea Nuova Password")
        win.geometry("550x500")
        
        frame = ttk.Frame(win, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Sito/Applicazione:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, pady=8)
        site_entry = ttk.Entry(frame, width=45, font=('Arial', 10))
        site_entry.grid(row=0, column=1, pady=8, padx=5)
        
        ttk.Label(frame, text="Username/Email:", font=('Arial', 10, 'bold')).grid(row=1, column=0, sticky=tk.W, pady=8)
        username_entry = ttk.Entry(frame, width=45, font=('Arial', 10))
        username_entry.grid(row=1, column=1, pady=8, padx=5)
        
        ttk.Label(frame, text="Password:", font=('Arial', 10, 'bold')).grid(row=2, column=0, sticky=tk.W, pady=8)
        password_entry = ttk.Entry(frame, width=45, font=('Arial', 10))
        password_entry.grid(row=2, column=1, pady=8, padx=5)
        
        ttk.Label(frame, text="Note:", font=('Arial', 10, 'bold')).grid(row=3, column=0, sticky=tk.W, pady=8)
        note_entry = ttk.Entry(frame, width=45, font=('Arial', 10))
        note_entry.grid(row=3, column=1, pady=8, padx=5)
        
        # Generatore password
        gen_frame = ttk.LabelFrame(frame, text="🎲 Generatore Password Casuale", padding="15")
        gen_frame.grid(row=4, column=0, columnspan=2, pady=15, sticky=tk.EW)
        
        settings_frame = ttk.Frame(gen_frame)
        settings_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(settings_frame, text="Lunghezza:").pack(side=tk.LEFT, padx=5)
        length_var = tk.IntVar(value=16)
        ttk.Spinbox(settings_frame, from_=8, to=64, textvariable=length_var, width=10).pack(side=tk.LEFT, padx=5)
        
        include_upper = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Maiuscole", variable=include_upper).pack(side=tk.LEFT, padx=5)
        
        include_numbers = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Numeri", variable=include_numbers).pack(side=tk.LEFT, padx=5)
        
        include_symbols = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Simboli", variable=include_symbols).pack(side=tk.LEFT, padx=5)
        
        def generate_password():
            chars = string.ascii_lowercase
            if include_upper.get():
                chars += string.ascii_uppercase
            if include_numbers.get():
                chars += string.digits
            if include_symbols.get():
                chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
            
            if not chars:
                chars = string.ascii_letters
            
            password = ''.join(secrets.choice(chars) for _ in range(length_var.get()))
            password_entry.delete(0, tk.END)
            password_entry.insert(0, password)
        
        ttk.Button(gen_frame, text="🎲 Genera Password", command=generate_password).pack(pady=5)
        
        def save_password():
            site = site_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            note = note_entry.get().strip()
            
            if not site or not username or not password:
                messagebox.showerror("Errore", "Compila almeno Sito, Username e Password!")
                return
            
            from datetime import datetime
            self.passwords.append({
                'site': site,
                'username': username,
                'password': password,
                'note': note,
                'created': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
            
            self.save_vault()
            self.refresh_list()
            win.destroy()
            messagebox.showinfo("✅ Successo", f"Password per '{site}' salvata correttamente!")
        
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="💾 Salva", command=save_password, width=15).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="❌ Annulla", command=win.destroy, width=15).pack(side=tk.LEFT, padx=10)
        
        site_entry.focus()
    
    def show_password_details(self):
        """Mostra dettagli password in una finestra"""
        selection = self.tree.selection()
        if not selection:
            return
        
        index = int(selection[0])
        pwd = self.passwords[index]
        
        win = tk.Toplevel(self.root)
        win.title(f"Dettagli: {pwd['site']}")
        win.geometry("500x400")
        
        frame = ttk.Frame(win, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text=f"Sito: {pwd['site']}", font=('Arial', 12, 'bold')).pack(pady=5, anchor=tk.W)
        ttk.Label(frame, text=f"Username: {pwd['username']}", font=('Arial', 11)).pack(pady=5, anchor=tk.W)
        ttk.Label(frame, text=f"Password: {pwd['password']}", font=('Arial', 11)).pack(pady=5, anchor=tk.W)
        ttk.Label(frame, text=f"Note: {pwd.get('note', 'N/A')}", font=('Arial', 11)).pack(pady=5, anchor=tk.W)
        ttk.Label(frame, text=f"Creata il: {pwd.get('created', 'N/A')}", font=('Arial', 10)).pack(pady=5, anchor=tk.W)
        
        ttk.Button(frame, text="Chiudi", command=win.destroy).pack(pady=20)
    
    def edit_password(self):
        """Modifica password selezionata"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Attenzione", "Seleziona una password da modificare!")
            return
        
        index = int(selection[0])
        pwd = self.passwords[index]
        
        win = tk.Toplevel(self.root)
        win.title(f"✏️ Modifica: {pwd['site']}")
        win.geometry("500x350")
        
        frame = ttk.Frame(win, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Sito:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, pady=8)
        site_entry = ttk.Entry(frame, width=40, font=('Arial', 10))
        site_entry.insert(0, pwd['site'])
        site_entry.grid(row=0, column=1, pady=8)
        
        ttk.Label(frame, text="Username:", font=('Arial', 10, 'bold')).grid(row=1, column=0, sticky=tk.W, pady=8)
        username_entry = ttk.Entry(frame, width=40, font=('Arial', 10))
        username_entry.insert(0, pwd['username'])
        username_entry.grid(row=1, column=1, pady=8)
        
        ttk.Label(frame, text="Password:", font=('Arial', 10, 'bold')).grid(row=2, column=0, sticky=tk.W, pady=8)
        password_entry = ttk.Entry(frame, width=40, font=('Arial', 10))
        password_entry.insert(0, pwd['password'])
        password_entry.grid(row=2, column=1, pady=8)
        
        ttk.Label(frame, text="Note:", font=('Arial', 10, 'bold')).grid(row=3, column=0, sticky=tk.W, pady=8)
        note_entry = ttk.Entry(frame, width=40, font=('Arial', 10))
        note_entry.insert(0, pwd.get('note', ''))
        note_entry.grid(row=3, column=1, pady=8)
        
        def save_changes():
            self.passwords[index] = {
                'site': site_entry.get().strip(),
                'username': username_entry.get().strip(),
                'password': password_entry.get().strip(),
                'note': note_entry.get().strip(),
                'created': pwd.get('created', 'N/A')
            }
            self.save_vault()
            self.refresh_list()
            win.destroy()
            messagebox.showinfo("✅ Successo", "Password modificata!")
        
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="💾 Salva", command=save_changes, width=15).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="❌ Annulla", command=win.destroy, width=15).pack(side=tk.LEFT, padx=10)
    
    def delete_password(self):
        """Elimina password selezionata"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Attenzione", "Seleziona una password da eliminare!")
            return
        
        index = int(selection[0])
        site_name = self.passwords[index]['site']
        
        if messagebox.askyesno("⚠️ Conferma Eliminazione", f"Sei sicuro di voler eliminare la password per '{site_name}'?"):
            del self.passwords[index]
            self.save_vault()
            self.password_visible.pop(index, None)
            self.refresh_list()
            messagebox.showinfo("✅ Successo", "Password eliminata!")
    
    def copy_password(self):
        """Copia la password negli appunti"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Attenzione", "Seleziona una password da copiare!")
            return
        
        index = int(selection[0])
        password = self.passwords[index]['password']
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        messagebox.showinfo("✅ Copiata", "Password copiata negli appunti!")
    
    def toggle_password_visibility(self):
        """Mostra/nascondi password"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Attenzione", "Seleziona una password!")
            return
        
        index = int(selection[0])
        self.password_visible[index] = not self.password_visible.get(index, False)
        self.filter_passwords()
    
    def export_vault(self):
        """Esporta il vault"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".vault",
            filetypes=[("Vault files", "*.vault"), ("All files", "*.*")],
            initialfile=f"backup_{self.vault_file}"
        )
        if filename:
            try:
                with open(self.vault_file, 'rb') as f:
                    data = f.read()
                with open(filename, 'wb') as f:
                    f.write(data)
                messagebox.showinfo("✅ Successo", f"Vault esportato in:\n{filename}")
            except Exception as e:
                messagebox.showerror("Errore", f"Impossibile esportare: {str(e)}")
    
    def import_vault(self):
        """Importa un vault"""
        filename = filedialog.askopenfilename(
            title="Seleziona vault da importare",
            filetypes=[("Vault files", "*.vault"), ("All files", "*.*")]
        )
        if filename:
            self.vault_file = filename
            messagebox.showinfo("Info", "Vault importato! Riapri il vault con la password corretta.")
            self.lock_vault()
    
    def search_window(self):
        """Finestra di ricerca avanzata"""
        win = tk.Toplevel(self.root)
        win.title("🔍 Ricerca Avanzata")
        win.geometry("450x300")
        
        frame = ttk.Frame(win, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Termine di ricerca:", font=('Arial', 11, 'bold')).pack(pady=10)
        
        search_var = tk.StringVar()
        search_entry = ttk.Entry(frame, textvariable=search_var, width=50, font=('Arial', 10))
        search_entry.pack(pady=5)
        
        ttk.Label(frame, text="Cerca in:", font=('Arial', 10)).pack(pady=10)
        
        category_var = tk.StringVar(value="Tutti")
        ttk.Radiobutton(frame, text="🌐 Tutti i campi", variable=category_var, value="Tutti").pack(anchor=tk.W, padx=50)
        ttk.Radiobutton(frame, text="📍 Solo Sito", variable=category_var, value="Sito").pack(anchor=tk.W, padx=50)
        ttk.Radiobutton(frame, text="👤 Solo Username", variable=category_var, value="Username").pack(anchor=tk.W, padx=50)
        ttk.Radiobutton(frame, text="📝 Solo Note", variable=category_var, value="Note").pack(anchor=tk.W, padx=50)
        
        def do_search():
            term = search_var.get().lower()
            cat = category_var.get()
            
            if not term:
                messagebox.showwarning("Attenzione", "Inserisci un termine di ricerca!")
                return
            
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            found = 0
            for i, pwd in enumerate(self.passwords):
                match = False
                if cat == "Tutti":
                    match = term in pwd['site'].lower() or term in pwd['username'].lower() or term in pwd.get('note', '').lower()
                elif cat == "Sito":
                    match = term in pwd['site'].lower()
                elif cat == "Username":
                    match = term in pwd['username'].lower()
                elif cat == "Note":
                    match = term in pwd.get('note', '').lower()
                
                if match:
                    found += 1
                    password_display = '●' * 10
                    self.tree.insert('', tk.END, values=(
                        pwd['site'],
                        pwd['username'],
                        password_display,
                        pwd.get('note', '')[:50],
                        pwd.get('created', 'N/A')
                    ), iid=i)
            
            win.destroy()
            messagebox.showinfo("Risultati", f"Trovate {found} password corrispondenti!")
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="🔍 Cerca", command=do_search, width=15).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="❌ Annulla", command=win.destroy, width=15).pack(side=tk.LEFT, padx=10)
        
        search_entry.focus()
    
    def lock_vault(self):
        """Blocca il vault e torna al menu"""
        self.master_password = None
        self.passwords = []
        self.is_unlocked = False
        self.password_visible = {}
        self.create_vault_menu()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()