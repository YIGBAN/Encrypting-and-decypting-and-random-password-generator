#Yanis Nagirnyak, encrypting and decrypting a phrase, and random password generator
#ENCRYPTOMATIC-----------------------------------------------------------------------

import tkinter as tk
from tkinter import ttk
import string
import random

class EncryptionTool:
    def __init__(self, master):
        self.master = master
        self.master.title("Encryptomatic")

        # Widgets
        self.input_label = ttk.Label(master, text="Enter Text:")
        self.input_entry = ttk.Entry(master, width=40)

        self.password_label = ttk.Label(master, text="Enter Password:")
        self.password_entry = ttk.Entry(master, show="*", width=40)

        self.password_length_label = ttk.Label(master, text="Password Length:")
        self.password_length_slider = ttk.Scale(master, from_=8, to=16, orient="horizontal", length=200, command=self.update_password_length)
        self.password_length_display = ttk.Label(master, text="Length: 8")

        # Layout
        self.password_length_label.grid(row=5, column=0, sticky="W", padx=10, pady=5)
        self.password_length_slider.grid(row=5, column=1, columnspan=2, padx=10, pady=5)
        self.password_length_display.grid(row=5, column=3, padx=10, pady=5)

        self.generate_button = ttk.Button(master, text="Generate Password", command=self.generate_password)
        self.generate_button.grid(row=6, column=1, columnspan=2, pady=5)
        self.encrypt_button = ttk.Button(master, text="Encrypt", command=self.encrypt_text)
        self.decrypt_button = ttk.Button(master, text="Decrypt", command=self.decrypt_text)

        self.output_label = ttk.Label(master, text="Result:")
        self.output_entry = ttk.Entry(master, state="readonly", width=40)

        self.password_generate_button = ttk.Button(master, text="Generate Password", command=self.generate_password)

        # Layout widgets
        self.input_label.grid(row=0, column=0, sticky="W", padx=10, pady=5)
        self.input_entry.grid(row=0, column=1, columnspan=2, padx=10, pady=5)

        self.password_label.grid(row=1, column=0, sticky="W", padx=10, pady=5)
        self.password_entry.grid(row=1, column=1, columnspan=2, padx=10, pady=5)

        self.encrypt_button.grid(row=2, column=1, pady=5)
        self.decrypt_button.grid(row=2, column=2, pady=5)

        self.output_label.grid(row=3, column=0, sticky="W", padx=10, pady=5)
        self.output_entry.grid(row=3, column=1, columnspan=2, padx=10, pady=5)

    
    #Functions
    def update_password_length(self, value):
        rounded_value = round(float(value))
        self.password_length_display.config(text=f"Length: {int(rounded_value)}")

    def generate_password(self):
        length = int(self.password_length_slider.get())
        random_password = self._generate_password(length)
        self.output_entry.configure(state="normal")
        self.output_entry.delete(0, tk.END)
        self.output_entry.insert(0, random_password)
        self.output_entry.configure(state="readonly")

    def encrypt_text(self):
        user_input = self.input_entry.get().lower()
        password = self.password_entry.get()
        encrypted_text = self.substitution_cipher(user_input, password)
        self.output_entry.configure(state="normal")
        self.output_entry.delete(0, tk.END)
        self.output_entry.insert(0, encrypted_text)
        self.output_entry.configure(state="readonly")

    def decrypt_text(self):
        encrypted_text = self.input_entry.get()
        password = self.password_entry.get()
        decrypted_text = self.substitution_cipher(encrypted_text, password, encrypt=False)
        self.output_entry.configure(state="normal")
        self.output_entry.delete(0, tk.END)
        self.output_entry.insert(0, decrypted_text)
        self.output_entry.configure(state="readonly")

    def substitution_cipher(self, text, key, encrypt=True):
        if encrypt:
            if len(key) == len(string.ascii_lowercase):
                translation_table = str.maketrans(string.ascii_lowercase, key)
                encrypted_text = text.translate(translation_table)
                return encrypted_text
            else:
                raise ValueError("Key length must be equal to the length of the alphabet.")
        else:
            reverse_key = str.maketrans(key, string.ascii_lowercase)
            decrypted_text = text.translate(reverse_key)
            return decrypted_text

    def _generate_password(self, length):
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        return password


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionTool(root)
    root.mainloop()
