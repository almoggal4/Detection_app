import select
import pickle
from Server.Preparation_For_Encyption import *
from Server.Encryption_And_Decryption import *
import base64
import os.path
import os
import matplotlib.pyplot as plt
import datetime
import ntpath
# connection setting:
from Server.Communication_Settings import *
import socket


Listen = 5

# data:
Public_Key = [0, 0]
Symmetrical_Keys = []
Length_Username = 4
Length_Password = 4
Users = []
Default_Private_Key = 100


# multithreaded Python server.
def creating_server(host=Host, port=Port, listen=Listen):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(listen)
    inputs = [server_socket]
    RSA_server()
    print("Server created successfully")
    return server_socket, inputs


# gets the server running.
def activating_server(server_socket, inputs, database, listen=Listen):
    in_fds, out_fds, err_fds = select.select(inputs, [], [], listen)

    if len(in_fds) != 0:
        for current_client in in_fds:
            if current_client is server_socket:
                client_sock, client_address = current_client.accept()
                inputs.append(client_sock)
                print("connect from:", client_address)
                send_data_to_client(current_client, database)
            else:
                send_data_to_client(current_client, database)


def add_zeros(str1):
    length_of_msg = ''
    zeros = Max_Data_Size-len(str1)
    try:
        for zero in range(0, zeros):
            length_of_msg = length_of_msg + "0"
        length_of_msg = length_of_msg + str1
        return length_of_msg
    except:
        raise Exception("size too big")


# sending messages to the current active clients who asks for server's response.
def send(current_client, response):
    source = find_raddr(current_client)
    msg_decrypted = pickle.dumps(encryption(response, get_symmetrical_key_client(current_client)))
    packet = add_zeros(str(len(msg_decrypted))).encode() + msg_decrypted
    current_client.send(packet)
    print("Server send: ", response, "------ to", source)


def send_data_to_client(current_client, database):
    try:
        source = find_raddr(current_client)
        try:
            size = int(current_client.recv(Max_Data_Size))
            encrypted_msg = pickle.loads(current_client.recv(size + Max_Data_Size))
            message = decryption(encrypted_msg, get_symmetrical_key_client(current_client))
        except:
            return

        print("Server received data:", message, "------ from:", source)
        if message[0] == "request":
            if message[1] == "exit":
                print("Disconnected from: ", current_client, message[2])
                if message[2] != "":
                    database.unactive_user(message[2])
                send(current_client, ["confirmed", "exit"])
            if message[1] == "get_public_key":
                send(current_client,
                     ["confirmed", "public_key_sent", "Server", get_public_key()[0], get_public_key()[1]])
            if message[1] == "create_a_symmetrical_key":
                global Symmetrical_Keys
                symmetrical_key = get_symmetrical_key(int(message[4]))
                Symmetrical_Keys.append([current_client, symmetrical_key])
                send(current_client,
                     ["confirmed", "symmetrical_key_saved", "Server", get_public_key()[0], get_public_key()[1]])
            if message[1] == "create_new_user":
                send(current_client, new_user_check(message[2], message[3], database))
            if message[1] == "login_to_account":
                send(current_client, login_check(message[2], message[3], database))
            if message[1] == "insert_person_image":
                send(current_client, create_wanted_people(message[2], base64.b64decode(message[3]),
                                                                   message[4], database))
            if message[1] == "insert_gallery_folder":
                send(current_client, create_gallery(message[2], message[3], database))
            if message[1] == "insert_person_to_gallery":
                send(current_client, insert_person_to_gallery(message[2], base64.b64decode(message[3]),
                                                                   message[4], database))

    except EOFError:
        pass


def get_symmetrical_key_client(current_client):
    global Symmetrical_Keys
    for client_and_key in Symmetrical_Keys:
        if current_client == client_and_key[0]:
            return client_and_key[1]
    return Default_Private_Key


# finding the socrce of the client (programmer's comfort)
def find_raddr(client):
    current_client = client
    source = str(current_client)
    words = source.split(" ")
    counter = 1
    for word in words:
        if "raddr=" in word:
            source = word[6:] + words[counter]
            source = source[:-1]
        counter = counter + 1
    return source


# check the following:
# username - 1.username not in use already 2.username must be at list 4 letters
def new_user_check(username, password, database):
    if username == "Please Enter Your Username Here..." or not username:
        return ["error", "no_username", "Server"]
    if password == "Please Enter Your Password Here..." or not password:
        return ["error", "no_password", "Server"]
    if len(username) < Length_Username:
        return ["error",  "username_too_short", "Server"]
    if len(password) < Length_Password:
        return ["error", "password_too_short", "Server"]
    if not database.insert(username, password):
        return ["error", "username_exists", "Server"]

    return ["confirmed", "new_user_created", "Server"]


# password - 1.password must be at list 4 letters
def login_check(username, password, database):
    if not database.exists(username, password):
        return ["error", "username_not_matching_the_password", "Server"]
    if not database.active_user(username):
        return ["error", "account_is_already_being_use", "Server"]
    return ["confirmed", "login", "Server"]


def create_wanted_people(username, image, name, database):

    server_path = os.path.join(database.get_user_path(username),
                               str(datetime.datetime.now()).replace(':', ';').replace('.', ','), "wanted_people")
    os.makedirs(server_path)
    image_path = os.path.join(server_path, name)
    plt.savefig(image_path)
    created_file = open(image_path, "wb")
    created_file.write(image)
    created_file.close()
    return ["confirmed", "people_inserted", "Server"]  # don't actually get sent yet


def create_gallery(username, name, database):
    server_paths = os.listdir(database.get_user_path(username))
    server_path = os.path.join(database.get_user_path(username), server_paths[len(server_paths)-1],
                               str(datetime.datetime.now()).replace(':', ';').replace('.', ',') + "_" + name)
    print(server_path)
    os.mkdir(server_path)
    return ["confirmed", "gallery_created", "Server"] # don't actually get sent yet


def insert_person_to_gallery(username, image, name, database):
    server_paths = os.listdir(database.get_user_path(username))

    current_image = os.path.join(database.get_user_path(username), server_paths[len(server_paths) - 1])

    client_paths = os.listdir(current_image)

    image_path = os.path.join(database.get_user_path(username), server_paths[len(server_paths) - 1],
                              client_paths[0], name)
    print(image_path)
    plt.savefig(image_path)
    created_file = open(image_path, "wb")
    created_file.write(image)
    created_file.close()
    return ["confirmed", "people_inserted_to_gallery", "Server"]  # don't actually get sent yet