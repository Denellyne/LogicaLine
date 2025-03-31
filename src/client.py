
import socket
import threading
import sys

# Create a TCP/IP socket for the client
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Replace 'SERVER_IP' with the actual IP address of the server on your LAN
client.connect(('localhost', int(sys.argv[1])))

def receive_messages():
    """Continuously listens for messages from the server."""
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            if message:
                print(message)
        except:
            print("An error occurred. Disconnecting from the server.")
            client.close()
            break

def send_messages():
    """Reads user input and sends it to the server."""
    while True:
        message = input()
        message += '\n'
        if message:
            try:
                client.send(message.encode('utf-8'))
            except:
                print("Failed to send message. The server might be down.")
                break

if __name__ == "__main__":
    # Start threads for receiving and sending messages
    threading.Thread(target=receive_messages, daemon=True).start()
    send_messages()
