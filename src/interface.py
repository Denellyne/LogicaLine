import customtkinter as ctk
import subprocess
import sys
import threading
import platform
import tkinter

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class ChatApp(ctk.CTk):

    def __init__(self, proc):
        super().__init__()

        self.alias = "anon"

        self.proc = proc
        self.title("Prolog Chat")
        self.geometry("800x600")

        self.chat_frame = ctk.CTkFrame(self, corner_radius=10)
        self.chat_frame.pack(padx=10, pady=10, fill="both", expand=True)

        self.chat_scrollable = ctk.CTkScrollableFrame(self.chat_frame)
        self.chat_scrollable.pack(fill="both", expand=True)

        self.bind_mousewheel_to_scroll()

        self.input_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.input_frame.pack(padx=(10, 20), pady=(0, 10), fill="x")

        self.placeholder_text = "Type a message..."
        self.placeholder_color = "gray"
        self.default_fg_color = "white"

        self.message_entry = ctk.CTkTextbox(self.input_frame, height=35, border_width=1, corner_radius=7, wrap=ctk.WORD)
        self.message_entry.pack(side="left", padx=(10, 20), pady=10, expand=True, fill="both")

        self.min_lines = 1
        self.max_lines = 8
        self.line_height = 35

        self.message_entry.bind("<KeyRelease>", self.adjust_textbox_height)
        self.message_entry.bind("<Return>", self.adjust_textbox_height)
        self.message_entry.bind("<FocusIn>", self.adjust_textbox_height)
        self.message_entry.bind("<FocusOut>", self.adjust_textbox_height)


        self.message_entry.insert("1.0", self.placeholder_text)
        self.message_entry.configure(text_color=self.placeholder_color)

        self.message_entry.bind("<FocusIn>", self.clear_placeholder)
        self.message_entry.bind("<FocusOut>", self.add_placeholder)
        self.message_entry.bind("<Return>", self.send_message)
        self.message_entry.bind("<Shift-Return>", lambda e: None)
        self.message_entry.bind("<Key>", self.clear_placeholder)

        self.send_button = ctk.CTkButton(self.input_frame, text="Send", command=self.send_message, width=60)
        self.send_button.pack(side="left", pady=10)

        my_font = ctk.CTkFont(family="Courier", size=12)

        self.message_entry.configure(font=my_font)

        self.protocol("WM_DELETE_WINDOW", self.quit)

    def bind_mousewheel_to_scroll(self):
        canvas = self.chat_scrollable._parent_canvas

        def _on_mousewheel(event):
            canvas.yview_scroll(-1 * (event.delta // 120), "units")

        def _on_mousewheel_linux(event):
            canvas.yview_scroll(-1 if event.num == 4 else 1, "units")

        if platform.system() == "Windows" or platform.system() == "Darwin":
            self.chat_scrollable.bind_all("<MouseWheel>", _on_mousewheel)
        else:
            self.chat_scrollable.bind_all("<Button-4>", _on_mousewheel_linux)
            self.chat_scrollable.bind_all("<Button-5>", _on_mousewheel_linux)

    def adjust_textbox_height(self, event=None):
        content = self.message_entry.get("1.0", "end-1c")
        chars_per_line = 94
        logical_lines = content.split("\n")
        wrapped_lines = sum((len(line) // chars_per_line + 1) for line in logical_lines)
        num_lines = max(self.min_lines, min(self.max_lines, wrapped_lines))
        new_height = 35 + (num_lines - 1) * (self.line_height - 20)
        self.message_entry.configure(height=new_height)

    def clear_placeholder(self, event=None):
        current = self.message_entry.get("1.0", "end").strip()
        if current == self.placeholder_text:
            self.message_entry.delete("1.0", "end")
            self.message_entry.configure(text_color=self.default_fg_color)

    def add_placeholder(self, event=None):
        current = self.message_entry.get("1.0", "end").strip()
        if current == "":
            self.message_entry.insert("1.0", self.placeholder_text)
            self.message_entry.configure(text_color=self.placeholder_color)

    def quit(self):
        self.send_message(message="/quit")
        self.destroy()
        sys.exit()

    def send_message(self, event=None, message=None):
        if message is None:
            message = self.message_entry.get("1.0", "end").strip()

        if len(message) > 0 and message[0] == "/":
            message = message.split(" ")
            if message[0] == "/quit":
                quit()
            elif message[0] == "/alias":
                if (len(message) > 1):
                    self.alias = message[1]
            self.message_entry.delete("1.0", "end")
            self.add_placeholder()
        else:
            if message and message != self.placeholder_text:
                message = self.alias + ": " + message
                self.append_message(message, sender="user")
                self.proc.stdin.write(message + "\n")
                self.proc.stdin.flush()
                self.message_entry.delete("1.0", "end")
                self.add_placeholder()

        return "break"

    def receive_messages(self):
        for message in self.proc.stdout:
            message = message.strip()
            if message:
                self.chat_scrollable.after(0, self.append_message, message, "server")

    def append_message(self, message, sender="user"):
        bubble_frame = ctk.CTkFrame(self.chat_scrollable, fg_color="transparent")
        bubble_frame.pack(fill="x", pady=4, padx=10, anchor="w" if sender == "server" else "e")

        bubble_color = "#3a3a3a" if sender == "server" else "#295ecf"
        text_color = "white"

        bubble = ctk.CTkLabel(
            bubble_frame,
            text=message,
            fg_color=bubble_color,
            text_color=text_color,
            corner_radius=12,
            padx=10,
            pady=6,
            wraplength=500,
            justify="left"
        )
        bubble.pack(anchor="w" if sender == "server" else "e")

        self.chat_scrollable.update_idletasks()
        self.chat_scrollable._parent_canvas.yview_moveto(1.0)
        print('\a')


if __name__ == "__main__":
    # proc = subprocess.Popen(["client.exe" if platform.system() == "Windows" else "./client"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    proc = subprocess.Popen(["swipl", "client.pl"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    app = ChatApp(proc)
    threading.Thread(target=app.receive_messages, daemon=True).start()
    app.mainloop()

