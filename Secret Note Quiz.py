from tkinter import *
from tkinter import messagebox
from cryptography.fernet import Fernet
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

window = Tk()
window.title("Secret Notes")
window.config(pady=30, padx=30)
# window.minsize(width=400, height=600)


def save_encrypt():  
    title = title_entry.get()
    master = master_entry.get()
    secret = secret_text.get("1.0",END)

    if len(title) == 0 or len(secret) == 0 or len(master) == 0:
        messagebox.showinfo(title="Error!!", message="Please fill all blanks") 
    else:
        enc_secret = encode(master, secret)

        try:
            with open ("note.txt", "a") as f:
                f.write(title)
                f.write("\n")
                f.write(enc_secret)
                f.close()
        except FileNotFoundError:
            with open ("note.txt", "w") as f:
                f.write(title)
                f.write("\n")
                f.write(enc_secret)
                f.close()
        finally:
            title_entry.delete(0, END)
            master_entry.delete(0, END)
            secret_text.delete("1.0", END)
 

def decrpyt_secret():
    encryted_secret = secret_text.get("1.0",END)
    master_secret = master_entry.get()
    
    if len(encryted_secret) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!!!", message="Please fill the blanks")
    else:
        try:
            dec_secret = decode(master_secret, encryted_secret)
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", dec_secret)    
        except:
            messagebox.showinfo(title="Error!!!", message="Please enter encrypted text")

title_label = Label(text="Enter your title")
title_label.pack()

title_entry = Entry(width=30)
title_entry.pack()

secret_label = Label(text="Enter your secret")
secret_label.pack()

secret_text = Text(width=40, height=20)
secret_text.pack()

master_label = Label(text="Enter master key")
master_label.pack()

master_entry = Entry(width=30)
master_entry.pack(pady=10)

save_and_encrypt_button = Button(text="Save & Encrypt", command=save_encrypt)
save_and_encrypt_button.pack()

decrypt_button = Button(text="Decrypt", command=decrpyt_secret)
decrypt_button.pack(pady=10, side="bottom")















window.mainloop()