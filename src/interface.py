import customtkinter as ctk
import subprocess
import sys
import threading
import platform

# Appearance
ctk.set_appearance_mode("Dark")  # Options: "Dark", "Light", "System"
ctk.set_default_color_theme("blue")  # Options: "blue", "green", "dark-blue"

class ChatApp(ctk.CTk):
    def __init__(self, proc):

        self.proc = proc

        super().__init__()

        self.title("CustomTkinter Chat")
        self.geometry("400x600")
        self.resizable(False, False)

        # Frame for chat display
        self.chat_frame = ctk.CTkFrame(self, corner_radius=10)
        self.chat_frame.pack(padx=10, pady=10, fill="both", expand=True)

        # Scrollable textbox for chat messages
        self.chat_textbox = ctk.CTkTextbox(self.chat_frame, wrap="word", state="disabled")
        self.chat_textbox.pack(padx=10, pady=10, fill="both", expand=True)

        # Frame for message input
        self.input_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.input_frame.pack(padx=10, pady=(0, 10), fill="x")

        self.message_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Type a message...", width=280)
        self.message_entry.pack(side="left", padx=(0, 10), pady=10, expand=True)
        self.message_entry.bind("<Return>", self.send_message)

        self.send_button = ctk.CTkButton(self.input_frame, text="Send", command=self.send_message)
        self.send_button.pack(side="left", pady=10)

        self.protocol("WM_DELETE_WINDOW", self.quit)

    def quit(self):
        self.send_message(message = "/quit")
        self.destroy()
        sys.exit()

    def send_message(self, message = None, event=None):
        if (message == None): message = self.message_entry.get().strip()
        if message:
            self.proc.stdin.write(message + "\n")
            self.proc.stdin.flush()
            self.message_entry.delete(0, "end")

    def receive_messages(self):
        for message in self.proc.stdout:
            message = message.strip()
            if message:
                self.chat_textbox.after(0, self.append_message, message)

    def append_message(self, message):
        self.chat_textbox.configure(state="normal")
        self.chat_textbox.insert("end", f"{message}\n")
        self.chat_textbox.configure(state="disabled")
        self.chat_textbox.see("end")



if __name__ == "__main__":

    proc = subprocess.Popen(["swipl", "client.pl"], stdin = subprocess.PIPE, stdout = subprocess.PIPE, text = True)

    app = ChatApp(proc)

    threading.Thread(target=app.receive_messages, daemon = True).start()

    app.mainloop()



