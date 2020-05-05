#!/usr/bin/env python3

import socket
import threading
import tkinter
from tkinter import filedialog
import os
#from Cryptodome.Cipher import AES
#from Cryptodome.Random import get_random_bytes

def listen_thread():
    LISTENHOST = '192.168.51.212'
    LISTENPORT = 65431

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((LISTENHOST, LISTENPORT))
        s.listen()
        while True:
            conn_listen, addr_listen = s.accept()
            data = conn_listen.recv(1024)
            #filename_received = conn_listen.recv(1024)
            #filename_received = filename_received.decode()
            filename_received = "odebrany.pdf"

            # display the message  
            print('odebrana sciezka: '+filename_received)
            print('odebrana wiadomosc: '+data.decode())

            messages_display.config(state='normal')
            messages_display.insert(tkinter.INSERT, 'Twój przyjaciel: '+data.decode()+'\n')
            messages_display.config(state='disabled')
            #if is big file/attachment
            if filename_received != '':
                f = open(filename_received, 'wb')
                data = conn_listen.recv(1024)
                while(data):
                    # TODO progress bar
                    f.write(data)
                    data = conn_listen.recv(1024)
                f.close()
                
            conn_listen.close()

#def close_window():
#    sock.sendall(bytes("Twój przyjaciel rozłączył się", 'utf-8'))
#    sock.close()
#    root.destroy()

def send_fun():
    # connect to the other client
    SENDHOST = '192.168.51.208'
    SENDPORT = 65432
    sock_send =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_send.connect((SENDHOST, SENDPORT))

    global path
    filename = str(os.path.basename(path))

    # send the filename so that server knows if there is an attachment
    sock_send.sendall(bytes(filename, 'utf-8'))
    print('wyslana sciezka: '+filename)

    # send the content of input (message)
    message_string = message_input.get()
    sock_send.sendall(bytes(message_string, 'utf-8'))
    print('wyslana wiadomosc: '+message_string)
    messages_display.config(state='normal')
    messages_display.insert(tkinter.INSERT, 'Ty: '+message_string+'\n')
    messages_display.config(state='disabled')
    message_input.delete(0, 'end')

    # if there is an attachent (filename is not null), send the content of it
    if path != '':
        f = open(path, 'rb')
        path = ''
        # TODO progress bar
        data = f.read(1024)
        while(data):
            # TODO progress bar
            sock_send.sendall(data)
            data = f.read(1024)
        f.close()

    sock_send.close()

def attach_file():
    global path
    path = filedialog.askopenfilename(initialdir='/', title='Select File')
    attach_name = tkinter.Label(root, text=path)
    attach_name.place(x=20, y=360)


# global variables
path = ''

# run listen thread
listenthr = threading.Thread(target=listen_thread)
listenthr.start()

#create private and public key

# create user interface
root = tkinter.Tk(className='Your safe Internet communicator')
#root.protocol("WM_DELETE_WINDOW", close_window)
root.geometry("400x400")
messages_display = tkinter.Text(root)
messages_display.config(state='disabled')
messages_display.place(x=20, y=20, width=360, height=300)
message_input = tkinter.Entry(root)
message_input.place(x=20, y=340, width=200, height=20)
attachment_button = tkinter.Button(root, text="Attach", command=attach_file)
attachment_button.place(x=280, y=340, width=40, height=20)
send_button = tkinter.Button(root, text="Send", command=send_fun)
send_button.place(x=330, y=340, width=40, height=20)
root.mainloop()# your code goes here