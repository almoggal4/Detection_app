from Server.Preparation_For_Encyption import *
from Server.Encryption_And_Decryption import *
from Server.Detect_faces import *
import select
import pickle
import base64
import os.path
import os
import matplotlib.pyplot as plt
import ntpath
import socket
import shutil

# connection setting:
from Server.Communication_Settings import *
Listen = 5

# data:
Public_Key = [0, 0]
Symmetrical_Keys = []
Length_Username = 4
Length_Password = 4
Default_Private_Key = 100
types = ['.jpg', '.png']
new_folders = []
Active_Clients = []
Info_Clients = {}

# multithreaded Python server.
def creating_server(host=Host, port=Port, listen=Listen):
    global Active_Clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(listen)
    Active_Clients.append(server_socket)
    RSA_server()
    print("Server created successfully")
    return server_socket


# gets the server running.
def activating_server(server_socket, database, listen=Listen):
    global Active_Clients
    in_fds, out_fds, err_fds = select.select(Active_Clients, [], [], listen)
    if len(in_fds) != 0:
        for current_client in in_fds:
            if current_client is server_socket:
                client_sock, client_address = current_client.accept()
                Active_Clients.append(client_sock)
                Info_Clients[client_sock] = "no_username"
                print(Active_Clients)
                print("connect from:", client_address)
                print(client_sock, "and ", current_client)
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
    print("Server send: ", handle_message(response), "------ to", source)


def send_data_to_client(current_client, database):
    global Active_Clients
    try:
        source = find_raddr(current_client)
        try:
            msg = current_client.recv(Max_Data_Size)
            if len(msg) == 0:  # Force disconnect
                print("Force disconnect: ", current_client)
                Active_Clients.remove(current_client)
                return
            else:
                size = int(msg)
                encrypted_msg = pickle.loads(current_client.recv(size + Max_Data_Size))
                message = decryption(encrypted_msg, get_symmetrical_key_client(current_client))
        except ConnectionAbortedError and OSError:
            return

        print("Server received data:", handle_message(message), "------ from:", source)
        if message[0] == "request":
            if message[1] == "exit":
                Active_Clients.remove(current_client)
                print("Clean disconnect: ", current_client, message[2])
                if message[2] != "":
                    database.unactive_user(message[2])
                send(current_client, ["confirmed", "exit"])
                return
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
            if message[1] == "find_the_person":
                find_the_person(current_client, message[2], database)
            if message[1] == "get_me_new_history_folders":
                send(current_client, transfer_history_folders(message[2], database))
            if message[1] == "get_me_images_in_folders":
                transfer_history_images(current_client, message[2], database)

    except EOFError:
        pass


def handle_message(message):
    copy_message = []
    for sub_message in message:
        copy_message.append(sub_message)

    at = 0
    for sub_message in copy_message:
        if len(sub_message) > 100:
            copy_message[at] = "image data"
        at = at + 1
    return copy_message


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


# a function that unactive the client, when needed.
#def unactive_client(current_client):
    #global Active_Clients, Info_Clients
    #for disconnected_client in Active_Clients:
        #if current_client == disconnected_client:




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
    #global
    if not database.exists(username, password):
        return ["error", "username_not_matching_the_password", "Server"]
    if not database.active_user(username):
        return ["error", "account_is_already_being_use", "Server"]
    return ["confirmed", "login", "Server"]


def create_wanted_people(username, image, name, database):
    delete_non_useful_data(username, database)
    server_path = os.path.join(database.get_user_path(username), name.split('.')[0])
    dup = False
    counter = 0
    dup_path = os.path.join(server_path + str(counter))
    while not dup:  # if the user search again for the same image\person\name
        if os.path.isdir(dup_path):
            counter = counter + 1
            time.sleep(0.1)  # the computer is too fast.
            dup_path = os.path.join(server_path + str(counter))
        else:
            os.makedirs(dup_path)
            dup = True

    image_path = os.path.join(dup_path, name)
    plt.savefig(image_path)
    created_file = open(image_path, "wb")
    created_file.write(image)
    created_file.close()

    number_of_faces = is_face(image_path)
    if number_of_faces == 1:
        return ["confirmed", "person_inserted", "Server"]
    if number_of_faces == 2:
        # don't actually get sent, because it dosen't make a difference
        return ["error", "more_then_one_face", "Server"]
    if number_of_faces == 0:
        # don't actually get sent, because it dosen't make a difference
        return ["error", "no_faces_found", "Server"]


# deletes from the history of the user all the non useful data like processes the weren't finished
def delete_non_useful_data(username, database):
    user_path = database.get_user_path(username)
    people = os.listdir(user_path)
    for potential_person in people:
        person_path = os.path.join(user_path, potential_person)
        sub_folders = os.listdir(person_path)
        if len(sub_folders) != 3 and os.path.isdir(person_path):  # unnecessary history data
            shutil.rmtree(person_path)


def create_gallery(username, name, database):
    user_path = database.get_user_path(username)
    newest = (max([os.path.join(user_path, d) for d in os.listdir(user_path)], key=os.path.getmtime))
    server_path = os.path.join(newest, name)
    os.mkdir(server_path)
    return ["confirmed", "gallery_created", "Server"]  # don't actually get sent yet


def insert_person_to_gallery(username, image, name, database):

    user_path = database.get_user_path(username)
    newest = (max([os.path.join(user_path, d) for d in os.listdir(user_path)], key=os.path.getmtime))

    client_paths = os.listdir(newest)
    image_path = os.path.join(newest, client_paths[0], name)
    plt.savefig(image_path)
    created_file = open(image_path, "wb")
    created_file.write(image)
    created_file.close()
    return ["confirmed", "people_inserted_to_gallery", "Server"]  # don't actually get sent yet


def find_the_person(current_client, username, database):
    person_path = ''
    gallery_path = ''
    user_path = database.get_user_path(username)
    current_person = max([os.path.join(user_path, d) for d in os.listdir(user_path)], key=os.path.getmtime)
    files = os.listdir(current_person)
    files.reverse()  # to make the last gallery be chosen, if the user have changed the gallery.

    for file in files:
        for type1 in types:
            if file.endswith(type1):
                person_path = file

    for file in files:
        if file != person_path:
            gallery_path = file

    person_path = current_person + "\\" + person_path
    gallery_path = current_person + "\\" + gallery_path
    fine_images = detect_people(gallery_path, person_path)

    user_path = database.get_user_path(username)
    newest = (max([os.path.join(user_path, d) for d in os.listdir(user_path)], key=os.path.getmtime))
    correct_images_dir = os.path.join(newest, "Correct_Images")
    if not os.path.isdir(correct_images_dir):
        os.makedirs(correct_images_dir)  # mkdir

    for file_name in fine_images:
        file = gallery_path + "\\" + file_name

        with open(file, "rb") as f:
            data = f.read()
        f.close()

        image_path = os.path.join(correct_images_dir, file_name)

        plt.savefig(image_path)
        created_file = open(image_path, "wb")
        created_file.write(data)
        created_file.close()

        send(current_client,
             ["confirmed", "person in this image", ntpath.basename(file), base64.b64encode(data), "Server"])
        time.sleep(0.01)  # waiting for the client to save the image and be ready to receive another one
    send(current_client, ["confirmed", "no more images found", "Server"])


def transfer_history_folders(username, database):
    global new_folders
    user_path = database.get_user_path(username)
    # send only the new history folders
    all_folders = os.listdir(user_path)
    old_folders = database.get_history_folders(username)
    new_folders = list(set(all_folders) - set(old_folders))
    for folder in new_folders:
        database.insert_user_history_folder(username, folder)

    msg_folders = str(new_folders).strip('[]')
    return ["confirmed", "here_are_the_history_folders", msg_folders, "Server"]


def transfer_history_images(current_client, username, database):
    global new_folders
    for folder in new_folders:
        folder_path = os.path.join(database.get_user_path(username), folder)
        correct_images_path = (max([os.path.join(folder_path, d) for d in os.listdir(folder_path)], key=os.path.getmtime))
        person_path = (min([os.path.join(folder_path, d) for d in os.listdir(folder_path)], key=os.path.getmtime))
        sub_folders = os.listdir(folder_path)
        gallery_path = ''
        for sub_folder in sub_folders:
            if sub_folder != ntpath.basename(correct_images_path) and sub_folder != ntpath.basename(person_path):
                gallery_path = os.path.join(folder_path, sub_folder)

        with open(person_path, "rb") as f:
            data = f.read()
        f.close()

        #  [confirmed, action, folder, sub folder, name of image, image data server]
        send(current_client, ["confirmed", "insert_image_to_history", folder, "Person",
                              ntpath.basename(person_path), base64.b64encode(data), "Server"])

        create_history_message_files(current_client, folder, correct_images_path, "Correct")
        create_history_message_files(current_client, folder, gallery_path, "Gallery")

    send(current_client, ["confirmed", "no more history files", "Server"])


def create_history_message_files(current_client, folder, history_folder, name):
    history_images = os.listdir(history_folder)
    for image in history_images:
        time.sleep(1)  # waiting for the client to save the image and be ready to receive another one
        image_path = os.path.join(history_folder, image)
        with open(image_path, "rb") as f:
            data = f.read()
        f.close()

        #  [confirmed, action, folder, sub folder, name of image, image data server]
        send(current_client, ["confirmed", "insert_image_to_history", folder, name,
                              ntpath.basename(image_path), base64.b64encode(data), "Server"])
