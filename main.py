import pygame
import time
import os
import subprocess
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
#pygame.display.set_icon(pygame.image.load("./images/favicon.png"))

font = pygame.font.Font(None,20)
font2 = pygame.font.Font(None,100)
font3 = pygame.font.Font(None,40)

copyright = font.render('© 2025 by assistantmaster', True, (150,150,150))

pw = ""
pw_dec = ""
last_pw_check = 0
scroll = 0

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
            if pw == "81b7bc7073fbe7cc2500ece776e7fcccc810e9fa851f06f0b428594eb771fbe4a7e142b43ca48219d6590d69e2fb6942ac78ba1ba6202715c6d7e28fef46c112":
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
        with open(f"./passwords/{url_var.get()}.pw", "w") as f:
            f.write(f'{encrypt(username_var.get().encode()).decode()}\n{encrypt(password_var.get().encode()).decode()}')
        root.destroy()

    def cancel():
        root.destroy()

    root = tkinter.Tk()
    root.title("Eintrag hinzufügen")
    root.resizable(False, False)
    root.geometry("330x170")

    frame = ttk.Frame(root, padding=12)
    frame.pack(fill="both", expand=True)

    ttk.Label(frame, text="Benutzername:").grid(row=0, column=0, sticky="w")
    username_var = tkinter.StringVar()
    username_entry = ttk.Entry(frame, textvariable=username_var, width=28)
    username_entry.grid(row=0, column=1, padx=6, pady=4)
    username_entry.focus()

    ttk.Label(frame, text="Passwort:").grid(row=1, column=0, sticky="w")
    password_var = tkinter.StringVar()
    password_entry = ttk.Entry(frame, textvariable=password_var, width=28, show="*")
    password_entry.grid(row=1, column=1, padx=6, pady=4)

    ttk.Label(frame, text="URL:").grid(row=2, column=0, sticky="w")
    url_var = tkinter.StringVar()
    url_entry = ttk.Entry(frame, textvariable=url_var, width=28)
    url_entry.grid(row=2, column=1, padx=6, pady=4)

    button_frame = ttk.Frame(frame)
    button_frame.grid(row=3, column=1, sticky="e", pady=(10,0))

    ttk.Button(button_frame, text="OK", command=submit).pack(side="right")
    ttk.Button(button_frame, text="Abbrechen", command=cancel).pack(side="right", padx=(0,8))

    root.bind('<Return>', lambda e: submit())

    root.mainloop()

def encrypt(plaintext):
    global pw_dec
    key = base64.urlsafe_b64encode(sha256(pw_dec.encode()).digest())
    f = Fernet(key)
    ciphertext = f.encrypt(plaintext)
    return ciphertext

def decrypt(ciphertext):
    global pw_dec
    key = base64.urlsafe_b64encode(sha256(pw_dec.encode()).digest())
    f = Fernet(key)
    plaintext = f.decrypt(ciphertext)
    return plaintext

running = True
while running:

    if pw == "":
        screen.fill((233, 233, 228))
        pw_warning = font2.render('Bitte gib das Passwort ein!', True, (0, 0, 0))
        screen.blit(pw_warning, (screen.get_width() // 2 - pw_warning.get_width() // 2, screen.get_height() // 2 - pw_warning.get_height()))
        pygame.display.flip()
        ask_for_password()

    elif pw == "81b7bc7073fbe7cc2500ece776e7fcccc810e9fa851f06f0b428594eb771fbe4a7e142b43ca48219d6590d69e2fb6942ac78ba1ba6202715c6d7e28fef46c112":

        timeleft = 300 - (int(time.time()) - last_pw_check)
        timeleftmin = int(timeleft//60)
        timeleftsec = int(timeleft%60)
        if timeleftsec < 10:
            timeleftsec = f"0{timeleftsec}"
        timedisplay = font3.render(f'{timeleftmin}:{timeleftsec}', True, (0, 0, 0))

        screen.fill((233, 233, 228))
        screen.blit(timedisplay, (20, 20))
        adddisplay = font2.render('+', True, (0, 0, 0))
        screen.blit(adddisplay, (0, 600))

        if last_pw_check + 300 <= int(time.time()):
            pw = ""
            pw_dec = ""

        if not os.path.exists("./passwords"):
            os.mkdir("passwords")

        for index, file in enumerate(os.listdir("./passwords")):
            if file.endswith(".pw"):
                name = font3.render(file.removesuffix(".pw"), True, (0, 0, 0))
                screen.blit(name, (100, index * 50 - scroll * 50 + 20))
                with open(f"./passwords/{file}") as f:
                    lines = [s.strip() for s in f]
                    username = decrypt((lines[0] if len(lines) > 0 else "").encode()).decode()
                    password = decrypt((lines[1] if len(lines) > 1 else "").encode()).decode()
                username = font3.render(username, True, (0, 0, 0))
                screen.blit(username, (700, index * 50 - scroll * 50 + 20))#
                password = font3.render(password, True, (0, 0, 0))
                screen.blit(password, (980, index * 50 - scroll * 50 + 20))
                
        keys = pygame.key.get_pressed()

        for event in pygame.event.get():

            if event.type == pygame.MOUSEBUTTONUP and pygame.mouse.get_pos()[0] <= 100 and pygame.mouse.get_pos()[1] >= 600 and pygame.mouse.get_pos()[1] <= 700:
                new_password()

            if event.type == pygame.QUIT:
                running = False
        

    elif pw == "-1":
        running = False

    screen.blit(copyright, (0,700))

    pygame.display.flip()

pygame.quit()