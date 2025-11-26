import pygame
import time
import os
import hashlib
import tkinter
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet
from hashlib import sha256
import base64

pygame.init()

width = 1280 
height = 720

screen = pygame.display.set_mode((width, height))
pygame.display.set_caption("Passwortmanager")
pygame.display.set_icon(pygame.image.load("./images/favicon.jpg"))

font = pygame.font.Font(None,20)
font2 = pygame.font.Font(None,100)
font3 = pygame.font.Font(None,40)

copyright = font.render('© 2025 by assistantmaster', True, (150,150,150))

pw = ""
pw_dec = ""
last_pw_check = 0
scroll = 0
anzahl_passwords = 0
show_password = {}
del_show = []
pw_reset_img = pygame.transform.scale(pygame.image.load("./images/password_reset.png"), (50, 50))

def set_new_mpw(is_pw):
    if is_pw:
        def submit():
            global pw
            global pw_dec
            global master_pw
            global last_pw_check
            if not (old_password_var.get() and new_password_var.get() and new_password_confirm_var.get()):
                messagebox.showwarning("Fehler", "Passwort-Felder dürfen nicht leer sein")
            else:
                if old_password_var.get() == pw_dec and new_password_var.get() == new_password_confirm_var.get():
                    with open("./password.mpw", "w") as f:
                        f.write(hashlib.sha512(new_password_var.get().encode()).hexdigest())
                    
                    for index, file in enumerate(os.listdir("./passwords")):
                        with open(f"./passwords/{file}", "r") as f:
                            lines = [s.strip() for s in f]
                            username = decrypt((lines[0] if len(lines) > 0 else "").encode(), pw_dec).decode()
                            password = decrypt((lines[1] if len(lines) > 1 else "").encode(), pw_dec).decode()
                        with open(f"./passwords/{file}", "w") as f:
                            f.write(f'{encrypt(username.encode(), new_password_var.get()).decode()}\n{encrypt(password.encode(), new_password_var.get()).decode()}')

                    master_pw = hashlib.sha512(new_password_var.get().encode()).hexdigest()
                    pw = master_pw
                    pw_dec = new_password_var.get()
                    last_pw_check = int(time.time())
                    root.destroy()
                else:
                    messagebox.showwarning("Fehler", "Passwörter stimmen nicht überein")

    else:
        def submit():
            global pw
            global pw_dec
            global master_pw
            global last_pw_check
            if not (new_password_var.get() and new_password_confirm_var.get()):
                messagebox.showwarning("Fehler", "Passwort-Felder dürfen nicht leer sein")
            else:
                if new_password_var.get() == new_password_confirm_var.get():
                    with open("./password.mpw", "w") as f:
                        f.write(hashlib.sha512(new_password_var.get().encode()).hexdigest())

                    master_pw = hashlib.sha512(new_password_var.get().encode()).hexdigest()
                    pw = master_pw
                    pw_dec = new_password_var.get()
                    last_pw_check = int(time.time())
                    for file in os.listdir("./passwords"):
                        os.remove(f"./passwords/{file}")
                    root.destroy()
                else:
                    messagebox.showwarning("Fehler", "Passwörter stimmen nicht überein")

    def toggle_show():
        show = "" if show_var.get() else "*"
        for widget in frame.winfo_children():
            if isinstance(widget, ttk.Entry):
                widget.config(show=show)

    root = tkinter.Tk()
    root.title("Neues Masterpasswort")
    root.resizable(False, False)
    root.geometry("400x180")

    frame = ttk.Frame(root, padding=12)
    frame.pack(fill="both", expand=True)

    ttk.Label(frame, text="Altes Passwort:").grid(row=0, column=0, sticky="w")
    old_password_var = tkinter.StringVar()
    entry = ttk.Entry(frame, textvariable=old_password_var, show="*", width=26)
    entry.grid(row=0, column=1, padx=6, pady=6)
    entry.focus()

    ttk.Label(frame, text="Neues Passwort:").grid(row=1, column=0, sticky="w")
    new_password_var = tkinter.StringVar()
    entry = ttk.Entry(frame, textvariable=new_password_var, show="*", width=26)
    entry.grid(row=1, column=1, padx=6, pady=6)

    ttk.Label(frame, text="Neues Passwort bestätigen:").grid(row=2, column=0, sticky="w")
    new_password_confirm_var = tkinter.StringVar()
    entry = ttk.Entry(frame, textvariable=new_password_confirm_var, show="*", width=26)
    entry.grid(row=2, column=1, padx=6, pady=6)

    show_var = tkinter.BooleanVar(value=False)
    show_cb = ttk.Checkbutton(frame, text="anzeigen", variable=show_var, command=toggle_show)
    show_cb.grid(row=3, column=1, sticky="w")

    button_frame = ttk.Frame(frame)
    button_frame.grid(row=4, column=1, sticky="e", pady=(10,0))

    ok_btn = ttk.Button(button_frame, text="OK", command=submit)
    ok_btn.pack(side="right")

    cancel_btn = ttk.Button(button_frame, text="Abbrechen", command=root.destroy)
    cancel_btn.pack(side="right", padx=(0,8))

    error_label = ttk.Label(frame, text="", foreground="red")
    error_label.grid(row=3, column=1, sticky="w")

    root.bind('<Return>', lambda e: submit())
    root.mainloop()

def ask_for_password():
    def submit():
        global pw
        global pw_dec
        global last_pw_check
        pw_dec = password_var.get()
        pw = hashlib.sha512(pw_dec.encode()).hexdigest()
        if not pw:
            messagebox.showwarning("Fehler", "Passwort darf nicht leer sein")
        else:
            if pw == master_pw:
                last_pw_check = int(time.time())
                root.destroy()
                return pw_dec
            else:
                error_label.config(text="Falsches Passwort")

    def toggle_show():
        entry.config(show="" if show_var.get() else "*")

    def close():
        global pw
        root.destroy()
        pw = "-1"
        return -1

    root = tkinter.Tk()
    root.title("Passworteingabe")
    root.resizable(False, False)
    root.geometry("320x130")

    frame = ttk.Frame(root, padding=12)
    frame.pack(fill="both", expand=True)

    ttk.Label(frame, text="Passwort:").grid(row=0, column=0, sticky="w")
    password_var = tkinter.StringVar()
    entry = ttk.Entry(frame, textvariable=password_var, show="*", width=26)
    entry.grid(row=0, column=1, padx=6, pady=6)
    entry.focus()

    show_var = tkinter.BooleanVar(value=False)
    show_cb = ttk.Checkbutton(frame, text="anzeigen", variable=show_var, command=toggle_show)
    show_cb.grid(row=1, column=1, sticky="w")

    button_frame = ttk.Frame(frame)
    button_frame.grid(row=2, column=1, sticky="e", pady=(10,0))

    ok_btn = ttk.Button(button_frame, text="OK", command=submit)
    ok_btn.pack(side="right")

    cancel_btn = ttk.Button(button_frame, text="Abbrechen", command=close)
    cancel_btn.pack(side="right", padx=(0,8))

    error_label = ttk.Label(frame, text="", foreground="red")
    error_label.grid(row=3, column=1, sticky="w")

    root.bind('<Return>', lambda e: submit())
    root.mainloop()

def new_password():
    def submit():
        invalid_chars = r'\/:*?"<>|'
        url_value = url_var.get()
        if any(c in url_value for c in invalid_chars):
            messagebox.showerror("Ungültige Eingabe", f"Folgende Zeichen sind nicht erlaubt: {invalid_chars}")
            return
        with open(f"./passwords/{url_value}.pw", "w") as f:
            f.write(f'{encrypt(username_var.get().encode(), pw_dec).decode()}\n{encrypt(password_var.get().encode(), pw_dec).decode()}')
        root.destroy()

    def cancel():
        root.destroy()

    def validate_url_input(event):
        invalid_chars = r'\/:*?"<>|'
        value = url_var.get()
        new_value = ''.join(c for c in value if c not in invalid_chars)
        if value != new_value:
            url_var.set(new_value)

    root = tkinter.Tk()
    root.title("Eintrag hinzufügen")
    root.resizable(False, False)
    root.geometry("330x170")

    frame = ttk.Frame(root, padding=12)
    frame.pack(fill="both", expand=True)

    ttk.Label(frame, text="Name / URL:").grid(row=0, column=0, sticky="w")
    url_var = tkinter.StringVar()
    url_entry = ttk.Entry(frame, textvariable=url_var, width=28)
    url_entry.grid(row=0, column=1, padx=6, pady=4)
    url_entry.bind('<KeyRelease>', validate_url_input)

    ttk.Label(frame, text="Benutzername:").grid(row=1, column=0, sticky="w")
    username_var = tkinter.StringVar()
    username_entry = ttk.Entry(frame, textvariable=username_var, width=28)
    username_entry.grid(row=1, column=1, padx=6, pady=4)
    username_entry.focus()

    ttk.Label(frame, text="Passwort:").grid(row=2, column=0, sticky="w")
    password_var = tkinter.StringVar()
    password_entry = ttk.Entry(frame, textvariable=password_var, width=28, show="*")
    password_entry.grid(row=2, column=1, padx=6, pady=4)

    button_frame = ttk.Frame(frame)
    button_frame.grid(row=3, column=1, sticky="e", pady=(10,0))

    ttk.Button(button_frame, text="OK", command=submit).pack(side="right")
    ttk.Button(button_frame, text="Abbrechen", command=cancel).pack(side="right", padx=(0,8))

    root.bind('<Return>', lambda e: submit())

    root.mainloop()

def encrypt(plaintext, pw_dec):
    key = base64.urlsafe_b64encode(sha256(pw_dec.encode()).digest())
    f = Fernet(key)
    ciphertext = f.encrypt(plaintext)
    return ciphertext

def decrypt(ciphertext, pw_dec):
    key = base64.urlsafe_b64encode(sha256(pw_dec.encode()).digest())
    f = Fernet(key)
    plaintext = f.decrypt(ciphertext)
    return plaintext


if os.path.exists("./password.mpw"):
    with open(f"./password.mpw") as f:
        master_pw = str(f.read())
        if master_pw == "":
            screen.fill((233, 233, 228))
            pw_warning = font2.render('Bitte gib das Passwort ein!', True, (0, 0, 0))
            screen.blit(pw_warning, (screen.get_width() // 2 - pw_warning.get_width() // 2, screen.get_height() // 2 - pw_warning.get_height()))
            pygame.display.flip()
            set_new_mpw(False)
else:
    screen.fill((233, 233, 228))
    pw_warning = font2.render('Bitte gib das Passwort ein!', True, (0, 0, 0))
    screen.blit(pw_warning, (screen.get_width() // 2 - pw_warning.get_width() // 2, screen.get_height() // 2 - pw_warning.get_height()))
    pygame.display.flip()
    set_new_mpw(False)

running = True
while running:

    if pw == "":
        screen.fill((233, 233, 228))
        pw_warning = font2.render('Bitte gib das Passwort ein!', True, (0, 0, 0))
        screen.blit(pw_warning, (screen.get_width() // 2 - pw_warning.get_width() // 2, screen.get_height() // 2 - pw_warning.get_height()))
        pygame.display.flip()
        ask_for_password()

    elif pw == master_pw:

        timeleft = 300 - (int(time.time()) - last_pw_check)
        timeleftmin = int(timeleft//60)
        timeleftsec = int(timeleft%60)
        if timeleftsec < 10:
            timeleftsec = f"0{timeleftsec}"
        timedisplay = font3.render(f'{timeleftmin}:{timeleftsec}', True, (0, 0, 0))

        screen.fill((233, 233, 228))
        screen.blit(timedisplay, (20, 20))
        adddisplay = font2.render('+', True, (0, 0, 0))
        screen.blit(pw_reset_img, (0, 500))
        screen.blit(adddisplay, (0, 600))

        if last_pw_check + 300 <= int(time.time()):
            pw = ""
            pw_dec = ""

        if not os.path.exists("./passwords"):
            os.mkdir("passwords")

        anzahl_passwords = 0

        for index, file in enumerate(os.listdir("./passwords")):
            if file.endswith(".pw"):
                y = index * 50 - scroll * 50 + 20
                x_button_rect = pygame.Rect(150, y, 30, 30)
                del_show.append((file, x_button_rect))
                x_text = font3.render("X", True, (255, 0, 0))
                screen.blit(x_text, (x_button_rect.x + 7, x_button_rect.y))
                if file not in show_password:
                    show_password[file] = False
                name = font3.render(file.removesuffix(".pw"), True, (0, 0, 0))
                screen.blit(name, (200, index * 50 - scroll * 50 + 20))
                with open(f"./passwords/{file}") as f:
                    lines = [s.strip() for s in f]
                    username = decrypt((lines[0] if len(lines) > 0 else "").encode(), pw_dec).decode()
                    password = decrypt((lines[1] if len(lines) > 1 else "").encode(), pw_dec).decode()
                username = font3.render(username, True, (0, 0, 0))
                screen.blit(username, (700, index * 50 - scroll * 50 + 20))
                pwd_display = password if show_password[file] else "*****"
                pwd_text = font3.render(pwd_display, True, (0, 0, 0))
                screen.blit(pwd_text, (980, index * 50 - scroll * 50 + 20))
                anzahl_passwords += 1
                
        keys = pygame.key.get_pressed()

        for event in pygame.event.get():

            if event.type == pygame.MOUSEBUTTONUP and event.button == 1 and pygame.mouse.get_pos()[0] <= 100 and pygame.mouse.get_pos()[1] >= 600 and pygame.mouse.get_pos()[1] < 700:
                new_password()
            if event.type == pygame.MOUSEBUTTONUP and event.button == 1 and pygame.mouse.get_pos()[0] <= 100 and pygame.mouse.get_pos()[1] >= 500 and pygame.mouse.get_pos()[1] < 600:
                set_new_mpw(True)
            if event.type == pygame.MOUSEBUTTONUP and event.button == 1:
                mx, my = pygame.mouse.get_pos()
                for file, rect in del_show:
                    if rect.collidepoint(mx, my):
                        os.remove(f"./passwords/{file}")
                        break
                for index, file in enumerate(os.listdir("./passwords")):
                    if file.endswith(".pw"):
                        pwd_x = 980
                        pwd_y = index * 50 - scroll * 50 + 20
                        pwd_w = 250
                        pwd_h = 40

                        if pwd_x <= mx <= pwd_x + pwd_w and pwd_y <= my <= pwd_y + pwd_h:
                            show_password[file] = not show_password[file]

            if event.type == pygame.MOUSEWHEEL and event.y == 1 and scroll > 0:
                scroll -= 1
            if event.type == pygame.MOUSEWHEEL and event.y == -1 and scroll < anzahl_passwords:
                scroll -= -1

            if event.type == pygame.QUIT:
                running = False
        

    elif pw == "-1":
        running = False

    screen.blit(copyright, (0,700))

    pygame.display.flip()

pygame.quit()