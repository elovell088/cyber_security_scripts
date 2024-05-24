import tkinter as tk
from tkinter import Tk
from tkinter import ttk
from tkinter.font import Font
from PIL import ImageTk, Image
import sys
import pyttsx3

def handle_button_click():
  
    text = entry.get()

    if text.upper() == 'Q':
        print("Thanks for playing!")
        sys.exit()
    
    tts.say(text)
    tts.runAndWait()
    entry.delete(0, tk.END)
    
"""
def validateInput(passed_text):
    """"""
    valid_characters = ["-"]
    
    if passed_text.isalpha():
        pass
"""

def handle_enter_key(event):
    handle_button_click()


def clear_placeholder(event):
    # Clear the placeholder text when the user clicks inside
    if entry.get() == placeholder_text:
        entry.delete(0, tk.END)
        entry.configure(foreground="black")


################
# --- MAIN --- #
################
tts = pyttsx3.init()


## GUI CONFIG START ##
window = tk.Tk()
#window.iconbitmap("mcc.ico")

style = ttk.Style()
style.theme_use("clam")

window.title("Gary")
window.geometry("275x80")
window.configure(bg="#483D8B")

# --INPUT LABEL-- #
bold = Font()

style.configure("Colored.TLabel", foreground="white")
label = ttk.Label(window, text="Tell Gary to say something..", style="Colored.TLabel", background="#483D8B", padding=(2, 2))
label.pack()

# --TEXT BOX-- #
entry = tk.Entry(window, width=30, justify="center")
entry.pack(padx=4, pady=4)

placeholder_text = "Enter text here..."
entry.insert(0, placeholder_text)  # Set the initial placeholder text
entry.configure(foreground="#999999")  # Set the text color to a lighter shade


## -- BOTTOM LABEL -- ##
bottom_style = ttk.Style()
bottom_style.configure("Custom.TLabel", foreground="white", font=("TkDefaultFont", 7))
bottom_label = ttk.Label(window, text="Written by: Eric lovell | mccScripts\u2122", style="Custom.TLabel", justify="center", background="#483D8B", padding=(2, 2))
bottom_label.pack(side=tk.BOTTOM, anchor=tk.S)

## GUI CONFIG END ##

#Bind the Enter key event to the entry widget
entry.bind("<Return>", handle_enter_key)

#Bind the FocusIn event to clear the placeholder text
entry.bind("<FocusIn>", clear_placeholder)

#Start the main event loop
window.mainloop()
