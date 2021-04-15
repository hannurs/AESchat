#!/usr/bin/env python3

import socket
import threading
import tkinter
from tkinter import filedialog
from tkinter import ttk
import os
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA
from binascii import hexlify
import time

import sys

def listen_thread():
    LISTENHOST = '192.168.51.212'
    LISTENPORT = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((LISTENHOST, LISTENPORT))
        s.listen()
        global session_key
        while True:
            conn_listen, addr_listen = s.accept()
 
            if session_key == False:
                session_key_bytes = conn_listen.recv(1024)
                cipher_rsa = PKCS1_OAEP.new(private_key)
                session_key = cipher_rsa.decrypt(session_key_bytes)
                print("session key: "  + str(session_key))

            decrypt_mode = conn_listen.recv(20)
            decrypt_mode = decrypt_mode.decode()

            message = conn_listen.recv(1024)
            message = decrypt(message, decrypt_mode)
            message = message.decode()
            # print('odebrana wiadomosc: '+message)

            filename_received = conn_listen.recv(1024)
            filename_received = decrypt(filename_received, decrypt_mode)
            filename_received = filename_received.decode()
            # print('odebrany zalacznik: '+filename_received)
            

            # display the message       

            messages_display.config(state='normal')
            messages_display.insert(tkinter.INSERT, 'Twój przyjaciel: '+ message +'\n')
            messages_display.config(state='disabled')
            #if is big file/attachment
            if filename_received != '':
                f = open(filename_received+".enc", 'wb')
                data = conn_listen.recv(1024)
                # data = decrypt.data()
                while(data):
                    # TODO progress bar
                    f.write(data)
                    data = conn_listen.recv(1024)
                    # data = decrypt(data)
                f.close()
                decrypt_file(filename_received+".enc", decrypt_mode)
                
            conn_listen.close()

#def close_window():
#    sock.sendall(bytes("Twój przyjaciel rozłączył się", 'utf-8'))
#    sock.close()
#    root.destroy()

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)


def encrypt(plaintext):
    # global encrypt_mode
    print(sys.getsizeof(bytes(str(encrypt_mode.get()), "utf-8")))
    plaintext = pad(plaintext)

    if str(encrypt_mode.get()) == "CBC":    #size = 20   
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(plaintext)
    elif str(encrypt_mode.get()) == "ECB":
        cipher = AES.new(session_key, AES.MODE_ECB)
        return cipher.encrypt(plaintext)
    elif str(encrypt_mode.get()) == "CFB":
        cipher = AES.new(session_key, AES.MODE_CFB, iv)
    elif str(encrypt_mode.get()) == "OFB":
        cipher = AES.new(session_key, AES.MODE_OFB, iv)


def encrypt_file(path):
    filename = str(os.path.basename(path))
    with open(path, 'rb') as f:
        plaintext = f.read()
    enc_file = encrypt(plaintext)
    with open(path + ".enc", 'wb') as f:
        f.write(enc_file)

def decrypt(ciphertext, decrypt_mode):
    global encrypt_mode

    if decrypt_mode == "CBC":
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
    elif decrypt_mode == "ECB":
        cipher = AES.new(session_key, AES.MODE_ECB)

    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def decrypt_file(filename, decrypt_mode):
    with open(filename, 'rb') as f:
        ciphertext = f.read()
    plaintext = decrypt(ciphertext, decrypt_mode)
    with open(filename[:-4], 'wb') as f:
        f.write(plaintext)
    os.remove(filename)



def send_fun():
    # connect to the other client
    SENDHOST = '192.168.51.208'
    SENDPORT = 65432
    sock_send =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_send.connect((SENDHOST, SENDPORT))

    global path
    global filename
    global attach_name
    global progress_bar
    global session_key

    if session_key == False:
        # generate session key and send it
        # exchange_session_key()
        session_key = get_random_bytes(16)

        cipher_rsa = PKCS1_OAEP.new(recipients_public_key)
        enc_session_key = cipher_rsa.encrypt(session_key)
        sock_send.sendall(enc_session_key)
        # print("wyslany session key "+ str(enc_session_key))
        time.sleep(0.1)

    # send the AES encryption mode
    sock_send.sendall(bytes(str(encrypt_mode.get()), "utf-8"))
    #time.sleep(0.1)

    # send the content of input (message)
    print(filename)
    message_string = message_input.get()
    if message_string == '' or filename != '':
        message_string = message_string+"+załącznik: "+filename

    message_encrypted = encrypt(bytes(message_string, 'utf-8'))
    sock_send.sendall(message_encrypted)
    # print('wyslana wiadomosc: '+ str(message_encrypted))
    time.sleep(0.1)

    # display my message
    messages_display.config(state='normal')
    messages_display.insert(tkinter.INSERT, 'Ty: '+message_string+'\n')
    messages_display.config(state='disabled')
    message_input.delete(0, 'end')

    # send the filename so that server knows if there is an attachment
    filename_enc = encrypt(bytes(filename, 'utf-8'))
    sock_send.sendall(filename_enc)
    print('wyslany zalacznik: '+str(filename))
    time.sleep(0.1)

    # if there is an attachent (filename is not null), send the content of it
    if path != '':
        attach_name.destroy()
        encrypt_file(path)
        f = open(path+".enc", 'rb')
        filesize = os.stat(path).st_size
        step_in_progress = 100/(filesize/1024)
        #print("rozmiar: "+str(filesize))
        # TODO progress bar
        data = f.read(1024)
        # data = encrypt(data)
        while(data):
            # TODO progress bar
            sock_send.sendall(data)
            progress_bar['value'] += step_in_progress
            root.update_idletasks()
            data = f.read(1024)
            # data = encrypt(data)
        f.close()
        os.remove(path+".enc")
        path = ''
        filename = ''
        progress_bar.destroy()
    sock_send.close()

def attach_file():
    global path
    global filename
    global attach_name
    global progress_bar
    path = filedialog.askopenfilename(initialdir='/', title='Select File')
    filename = str(os.path.basename(path))
    attach_name = tkinter.Label(root, text=path)
    attach_name.place(x=20, y=520)
    progress_bar = ttk.Progressbar(root, orient='horizontal', mode='determinate', length=100)
    progress_bar.place(x=20, y=540, width=440, height=20)

def exchange_session_key():
    print("exchange session key")
    


def GUI_send_thread():
    global root
    global message_input
    global messages_display
    global progress_bar
    global attach_name
    global encrypt_mode
    # create user interface
    root = tkinter.Tk(className='Your safe Internet communicator')
    #root.protocol("WM_DELETE_WINDOW", close_window)
    root.geometry("600x600")

    mode_label = tkinter.Label(root, text="Encrypting Mode: ")
    mode_label.place(x=20, y=20)
    encrypt_mode = tkinter.StringVar()
    encrypt_mode.set("ECB")
    encrypt_mode_menu = tkinter.OptionMenu(root, encrypt_mode, "ECB", "CBC", "CFB", "OFB")
    encrypt_mode_menu.place(x=120, y=20, width=70, height=20)

    messages_display = tkinter.Text(root)
    messages_display.config(state='disabled')
    messages_display.place(x=20, y=60, width=560, height=420)
    message_input = tkinter.Entry(root)
    message_input.place(x=20, y=500, width=440, height=20)

    attachment_button = tkinter.Button(root, text="Attach", command=attach_file)
    attachment_button.place(x=480, y=500, width=40, height=20)
    send_button = tkinter.Button(root, text="Send", command=send_fun)
    send_button.place(x=530, y=500, width=40, height=20)
    root.mainloop()
# global variables
path = ''
filename = ''
attachname = ''
session_key = False
root = None

# generate private and public key
#private_key = RSA.generate(1024)
#public_key = private_key.publickey()
#private_pem = private_key.export_key().decode()
#public_pem = public_key.export_key().decode()
#with open('private_pem.pem', 'w') as pr_k:
#    pr_k.write(private_pem)
#with open('public_pem.pem', 'w') as pu_k:
#    pu_k.write(public_pem)

private_key = RSA.import_key(open('myprivate_pem.pem', 'r').read())
my_public_key = RSA.import_key(open('mypublic_pem.pem', 'r').read())
recipients_public_key = RSA.import_key(open('recipients_public_pem.pem', 'r').read())


# run listen thread
listenthr = threading.Thread(target=listen_thread)
listenthr.start()

GUIthr = threading.Thread(target=GUI_send_thread)
GUIthr.start()