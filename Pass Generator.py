import tkinter as tk
from tkinter import messagebox
import random
import string
import pyperclip

class PasswordGeneratorApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Generator")

        self.label_length = tk.Label(master, text="Password Length:")
        self.label_length.pack()

        self.length_var = tk.StringVar()
        self.entry_length = tk.Entry(master, textvariable=self.length_var)
        self.entry_length.pack()

        self.label_password = tk.Label(master, text="Generated Password:")
        self.label_password.pack()

        self.password_var = tk.StringVar()
        self.entry_password = tk.Entry(master, textvariable=self.password_var, state="readonly")
        self.entry_password.pack()

        self.generate_button = tk.Button(master, text="Generate Password", command=self.generate_password)
        self.generate_button.pack()

        self.copy_button = tk.Button(master, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.pack()

    def generate_password(self):
        try:
            length = int(self.length_var.get())
            if length <= 0:
                raise ValueError("Password length must be greater than 0.")
            password = self.generate_random_password(length)
            self.password_var.set(password)
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def generate_random_password(self, length):
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))

    def copy_to_clipboard(self):
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
