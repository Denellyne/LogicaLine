import customtkinter as ctk
import subprocess
import sys
import threading
import platform
import tkinter
import time
import random
from datetime import datetime


ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class ChatApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.getting_internal_alias = False
        self.session_id = "#-1"

        self.alias = "anon"
        self.proc = None

        self.message_widgets = []
        self.max_messages = 100

        self.title("Logica Line")
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

        self.message_entry = ctk.CTkTextbox(self.input_frame, height=35, border_width=1, corner_radius=7, wrap=ctk.WORD, undo=True)
        self.message_entry.pack(side="left", padx=(10, 20), pady=10, expand=True, fill="both")

        self.min_lines = 1
        self.max_lines = 30
        self.line_height = 35

        self.message_entry.bind("<Control-z>", self.undo)
        self.message_entry.bind("<Control-a>", self.select_all)
        self.message_entry.bind("<Up>", self.undo)
        self.message_entry.bind("<Down>", self.redo)

        self.message_entry.bind("<KeyRelease>", self.adjust_textbox_height)

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

        self.bind("<Key>", self.on_try_to_write)
        self.bind("<Control-c>", self.ignore_action)
        self.bind("<FocusIn>", self.on_select_window)
        self.bind("<FocusOut>", self.on_deselect_window)
        self.current_main_window_focus = True
        self.last_time_sound_played = 0
        self.notification_cooldown = 1

        self.protocol("WM_DELETE_WINDOW", self.close)

    def redo(self, event=None):
        try:
            self.message_entry.edit_redo()
        except tkinter.TclError:
            pass
        return "break"

    def undo(self, event=None):
        try:
            self.message_entry.edit_undo()
        except tkinter.TclError:
            pass
        return "break"

    def select_all(self, event=None):
        self.message_entry.tag_add("sel", "1.0", "end-1c")
        return "break"

    def ignore_action(self, event=None):
        return None

    def block_action(self, event=None):
        return "break"

    def on_try_to_write(self, event=None):
        if event != None and event.keysym in ["Shift_L", "Shift_R", "Control_L", "Control_R"]:
            return "break"
        self.message_entry.focus_set()
        return "break"

    def on_select_window(self, event=None):
        self.current_main_window_focus = True

    def on_deselect_window(self, event=None):
        self.current_main_window_focus = False

    def bind_mousewheel_to_scroll(self):
        canvas = self.chat_scrollable._parent_canvas

        def _on_mousewheel(event):
            canvas.yview_scroll(-1 * (event.delta // 120), "units")

        def _on_mousewheel_linux(event):
            canvas.yview_scroll(-1 if event.num == 4 else 1, "units")

        def bind_wheel_events(event):
            if platform.system() in ["Windows", "Darwin"]:
                self.chat_scrollable.bind_all("<MouseWheel>", _on_mousewheel)
            else:
                self.chat_scrollable.bind_all("<Button-4>", _on_mousewheel_linux)
                self.chat_scrollable.bind_all("<Button-5>", _on_mousewheel_linux)

        def unbind_wheel_events(event):
            if platform.system() in ["Windows", "Darwin"]:
                self.chat_scrollable.unbind_all("<MouseWheel>")
            else:
                self.chat_scrollable.unbind_all("<Button-4>")
                self.chat_scrollable.unbind_all("<Button-5>")

        self.chat_scrollable.bind("<Enter>", bind_wheel_events)
        self.chat_scrollable.bind("<Leave>", unbind_wheel_events)

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

    def send_message(self, event=None, message=None):
        if message == None:
            message = self.message_entry.get("1.0", "end").strip()

        if len(message) > 0 and message[0] == "/":
            message = message.split(" ")
            if message[0] == "/connect":
                if len(message) == 2:
                    port = ""
                    ip = ""
                    if len(message[1].split(":")) == 1:
                        port = message[1]
                        ip = ""
                    else:
                        port = message[1].split(":")[1]
                        ip = message[1].split(":")[0]
                    self.connect(port, ip)
                elif len(message) == 3:
                    self.connect(message[2], message[1])
            elif message[0] == "/quit" or message[0] == "/disconnect":
                if self.proc == None:
                    if message[0] == "/quit":
                        self.close()
                else:
                    try:
                        self.proc.stdin.write("/quit\n")
                        self.proc.stdin.flush()
                    except:
                        print("Flush Error: send_message() -> self.proc.stdin.flush()")
                        if message[0] == "/quit":
                            self.close()
                    if message[0] == "/quit":
                        self.close()
            elif message[0] == "/alias":
                if (len(message) > 1):
                    self.alias = message[1]
            elif message[0] == "/notif_cd":
                if (len(message) > 1):
                    self.notification_cooldown = float(message[1])
            elif message[0] == "/help":
                self.append_message("Available Commands:\n/connect <ip>:<port>\n/connect <ip> <port>\n/connect <port>\n/disconnect\n/alias <text>\n/notif_cd <number_of_seconds>\n/quit\n/help\nInfo:\n/connect attemps to establish a connection to a server with a given ip+port or a given port, depending on if the server is local.\n/disconnect severs the connection you may have to a server.\n/alias changes the user name, default is 'anon'.\n/notif_cd changes the cooldown for the notification sound, which is in seconds and default is 0.12 seconds.\n/quit severs the connection to the server you may be connected to and closes the app.\n/help displays info on the commands for this app.")
        elif self.proc != None:
            if message and message != self.placeholder_text:
                if (self.getting_internal_alias):
                    self.alias = message
                    self.session_id = "#" + str(random.randint(0, 1000000000))
                    message = self.session_id + " " + message
                    self.getting_internal_alias = False
                else:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    message = self.session_id + " " + timestamp + " " + self.alias + ": " + message
                try:
                    self.proc.stdin.write(message + "\n")
                    self.proc.stdin.flush()
                except:
                    print("Flush Error: send_message() -> self.proc.stdin.flush()")
                    self.disconnect()
        self.message_entry.delete("1.0", "end")
        self.adjust_textbox_height()
        return "break"

    def receive_messages(self):
        if (self.proc == None):
            return
        for message in self.proc.stdout:
            message = message.strip()
            if message:
                self.chat_scrollable.after(0, self.append_message, message)

    def append_message(self, message):
        assignements = {"1":"user", "2":"server", "3":"server"}
        sender = assignements.get(message[0], "")
        if sender != "":
            message = message[1:]
        else:
            sender = "server"
            if (message == "Input the alias you wish to be called by:"):
                self.getting_internal_alias = True
        bubble_frame = ctk.CTkFrame(self.chat_scrollable, fg_color="transparent")
        bubble_frame.pack(fill="x", pady=4, padx=10)

        self.message_widgets.append(bubble_frame)

        if len(self.message_widgets) > self.max_messages:
            oldest = self.message_widgets.pop(0)
            oldest.destroy()

        bubble_color = "#3a3a3a" if sender == "server" else "#295ecf"
        text_color = "white"

        font_family = "Courier"
        font_size = 12

        chars_per_line = 67
        logical_lines = message.split("\n")
        wrapped_lines = sum((len(line) // chars_per_line) for line in logical_lines) + len(logical_lines)
        num_lines = max(self.min_lines, min(self.max_lines, wrapped_lines))
        height = 45 + (num_lines - 1) * (self.line_height - 20)

        bubble = ctk.CTkTextbox(
            bubble_frame,
            width=500,
            height=height,
            fg_color=bubble_color,
            text_color=text_color,
            corner_radius=12,
            wrap="word",
            font=(font_family, font_size),
            activate_scrollbars=False
        )
        bubble.insert("1.0", message)

        bubble.bind("<Key>", self.on_try_to_write)
        bubble.bind("<Control-v>", self.on_try_to_write)
        bubble.bind("<Control-x>", self.on_try_to_write)
        bubble.bind("<Control-Insert>", self.on_try_to_write)
        bubble.bind("<Shift-Insert>", self.ignore_action)
        bubble.bind("<Control-c>", self.ignore_action)

        def bind_scroll_behavior(widget):
            def on_mousewheel(event):
                if event.state & 0x0001:
                    return
                else:
                    widget.yview_scroll(-1 * (event.delta // 120), "units")
                    return "break"

            def on_mousewheel_linux(event):
                if event.state & 0x0001:
                    return
                direction = -1 if event.num == 4 else 1
                widget.yview_scroll(direction, "units")
                return "break"

            widget.bind("<Enter>", lambda e: widget.focus_set())
            widget.bind("<MouseWheel>", on_mousewheel)
            widget.bind("<Button-4>", on_mousewheel_linux)
            widget.bind("<Button-5>", on_mousewheel_linux)

        bind_scroll_behavior(bubble)

        bubble.configure(state="normal")

        if sender == "user":
            bubble.pack(anchor="e", padx=(100, 0))
        else:
            bubble.pack(anchor="w", padx=(0, 100))

        self.chat_scrollable.update_idletasks()
        self.chat_scrollable._parent_canvas.yview_moveto(1.0)

        if sender == "server":
            now = time.time()
            if self.current_main_window_focus and now - self.last_time_sound_played >= self.notification_cooldown:
                threading.Thread(target=self.play_notification_sound).start()

    def play_notification_sound(self):
        for i in range(3):
            print("\a", end="", flush=True)
            time.sleep(0.12)
        self.last_time_sound_played = time.time()

    def connect(self, port, ip=""):
        self.disconnect()
        #proc = subprocess.Popen(["client.exe" if platform.system() == "Windows" else "./client"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        if ip != "":
            self.proc = subprocess.Popen((f"swipl -q -f client.pl -g setup_client('{ip}',{port}).").split(" "), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        else:
            self.proc = subprocess.Popen((f"swipl -q -f client.pl -g setup_client({port}).").split(" "), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        threading.Thread(target=app.receive_messages, daemon=True).start()

    def disconnect(self):
        if (self.proc == None): return
        self.send_message(message="/disconnect")
        print("disconnecting!")
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.proc = None

    def close(self):
        if (self.proc != None):
            self.proc.kill()
        self.destroy()
        sys.exit()


if __name__ == "__main__":
    app = ChatApp()
    app.mainloop()
