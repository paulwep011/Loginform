import tkinter
from tkinter import messagebox
import re
import getpass

window = tkinter.Tk()
window.title("Login Form")
window.geometry('340x440')
window.configure(bg='#333333')
system_username = getpass.getuser()

def validate_password(password):
    if len(password) < 14:  # Changed from 12 to 14
        return False, "Password must be at least 14 characters long."

    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."

    common_passwords = r'\b(?:john|smith|password|1234|qwerty|admin|letmein|welcome|abc123|iloveyou|monkey)\b'
    if re.search(common_passwords, password.lower()):
        return False, "Password should not be a common word or easily guessable."

    return True, ""

def login():
    username = system_username
    password = password_entry.get()

    is_valid, message = validate_password(password)

    if username_entry.get() == username and is_valid:
        messagebox.showinfo(title="Login Success", message="You successfully logged in.")
    else:
        if not is_valid:
            messagebox.showerror(title="Error", message=message)
        else:
            messagebox.showerror(title="Error", message="Invalid login.")

frame = tkinter.Frame(bg='#333333')

login_label = tkinter.Label(frame, text="Login", bg='#333333', fg="#3399FF", font=("Arial", 30))
username_label = tkinter.Label(frame, text="Username", bg='#333333', fg="#3399FF", font=("Arial", 16))
username_entry = tkinter.Entry(frame, font=("Arial", 16))
password_label = tkinter.Label(frame, text="Password", bg='#333333', fg="#3399FF", font=("Arial", 16))
password_entry = tkinter.Entry(frame, show="*", font=("Arial", 16))
login_button = tkinter.Button(frame, text="Login", bg="#3399FF", fg="#FFFFFF", font=("Arial", 16), command=login)

login_label.grid(row=0, column=0, columnspan=2, sticky="news", pady=40)
username_label.grid(row=1, column=0)
username_entry.grid(row=1, column=1, pady=20)
password_label.grid(row=2, column=0)
password_entry.grid(row=2, column=1, pady=20)
login_button.grid(row=3, column=0, columnspan=2, pady=30)

frame.pack()

window.mainloop()
