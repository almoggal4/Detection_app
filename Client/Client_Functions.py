from Client.Handle_Images import *
from Client.Encryption_And_Decryption import *
from tkinter import DoubleVar, filedialog, ttk
from PIL import Image, ImageTk
import shutil
import socket
import pickle
import random
import base64
import ntpath
import matplotlib.pyplot as plt
import datetime
import time
import os

# connection setting:
from Client.Communication_Settings import *

#    backgrounds:
# Regulars:
Main_B = "Design\Photos\Backgrounds\\Main.jpg"
New_User_B = "Design\Photos\Backgrounds\\new_user.jpg"
Exists_User_B = "Design\Photos\Backgrounds\\exists_user.jpg"
Register_User_B = "Design\Photos\Backgrounds\\register_user_main.jpg"
How_To_Use_B = "Design\Photos\Backgrounds\\how_to_use.jpg"
Inputs_B = "Design\Photos\Backgrounds\\inputs.jpg"
Gallery_B = "Design\Photos\Backgrounds\\gallery.jpg"
History_B = "Design\Photos\Backgrounds\\history.jpg"
Wait_B = "Design\Photos\Backgrounds\\wait.jpg"
Undetermined_Pictures_B = "Design\Photos\Backgrounds\\undetermined_pictures.jpg"
Detection_Faces_B = "Design\Photos\Backgrounds\\detection_face.jpg"
Blank_B = "Design\Photos\Backgrounds\\blank.jpg"

# Errors:
No_UserName_B = "Design\Photos\Errors_New\\no_username.jpg"
No_Password_B = "Design\Photos\Errors_New\\no_password.jpg"
Unknown_User_B = "Design\Photos\Error_Exists\\wrong_username_or_password.jpg"
Username_Already_In_Use_B = "Design\Photos\Errors_New\\username_already_in_use.jpg"
Short_Username_B = "Design\Photos\Errors_New\\username_short.jpg"
Short_Password_B = "Design\Photos\Errors_New\\password_short.jpg"
Account_In_Use_B = "Design\Photos\Error_Exists\\wrong_username_or_password.jpg"

Invalid_Path_B = "Design\Photos\Error_Detection_Faces\\wrong_file_type.jpg"
No_Face_B = "Design\Photos\Error_Detection_Faces\\no_face.jpg"
Too_Much_Faces_B = "Design\Photos\Error_Detection_Faces\\too_much_faces.jpg"


# data:
Face_Founder_App_Path = "C:\\Program Files\\Face_Founder_App"
if not os.path.isdir(Face_Founder_App_Path):
    os.makedirs(Face_Founder_App_Path)
Public_key = [0, 0]
Symmetrical_Key = 100
Client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
Client.connect((Host, Port))
Root = tk.Tk()
Root.resizable(0, 0)
Hide = ""
image_counter = 0
images = []
background_image = None
Client_Path_Images = "C:\\Program Files\\Face_Founder_App\\Images"
Client_Path_History = "C:\\Program Files\\Face_Founder_App\\History"
file_types = [("Image File", '.jpg'), ("Image File", '.png')]
types = ['.jpg', '.png']
username_new_user = None
password_new_user = None
username_login = None
password_login = None
Person_Path = ''
correct_images = []


# communication with the server. a packet = [kind of command, the command, username if needed, password if needed].
# gets a response from the server and check it.
def send_data_to_server(data, client=Client, use_symmetrical_key=True):
    global Symmetrical_Keys
    print("Client sent: ", handle_message(data))
    if use_symmetrical_key:  # Encrypt
        msg_decrypted = pickle.dumps(encryption(data, Symmetrical_Key))
    else:  # A message to get a public key, encrypted without a public key - RSA
        msg_decrypted = pickle.dumps(encryption(data))
    packet = add_zeros(str(len(msg_decrypted))).encode() + msg_decrypted
    # if the client is about to send a message and the user is closing the program, and by doing this he is closing
    # the socket. clean exit.
    try:
        client.send(packet)
    except OSError:
        return
    if len(data) > 3:
        try:
            size = int(client.recv(Max_Data_Size))
        except ValueError:
            # the size is to small, that it is considerd not as an int.
            # so it means that one of the packet's the message is empty.
            size = 0
        encrypted_msg = pickle.loads(client.recv(size + Max_Data_Size))
        message = decryption(encrypted_msg, Symmetrical_Key)
        check(message, data[2], data[3])


# main window screen
def main_window(background=Main_B):
    global background_image
    for widget in Root.winfo_children():
        widget.destroy()

    image = Image.open(background)
    width, height = image.size
    my_canvas = tk.Canvas(Root, width=width, height=height)
    my_canvas.pack()

    Root.title("Detection App")
    background_image = ImageTk.PhotoImage(image)
    background_label = tk.Label(Root, image=background_image)
    background_label.place(relwidth=1, relheight=1)

    button_new_user = tk.Button(Root, text="New User", font=40,
                                command=(lambda: new_user(New_User_B)))
    button_new_user.place(relx=0.1, rely=0.6, relheight=0.2, relwidth=0.3)
    button_new_user.config(bg="#cccccc")
    button_exists_user = tk.Button(Root, text="Login", font=40,
                                   command=(lambda: login(Exists_User_B)))
    button_exists_user.place(relx=0.6, rely=0.6, relheight=0.2, relwidth=0.3)
    button_exists_user.config(bg="#cccccc")
    Root.protocol('WM_DELETE_WINDOW', lambda: close_window())
    Root.bind("<Return>", lambda event: None)  # changing the event when pressing enter.
    Root.mainloop()


def username_entry_check_new_user1(event):
    global username_new_user
    if username_new_user['fg'] == "grey":
        username_new_user.delete('0', "end")  # delete all the text in the entry
        username_new_user.config(fg='black', font='Helvetica 14 bold')


def username_entry_check_new_user2(event):
    global username_new_user
    if not username_new_user.get():
        username_new_user.config(fg='grey', font='Helvetica 12')
        username_new_user.insert("0", "Please Enter Your Username Here...")


def password_entry_check_new_user1(event):
    global password_new_user
    if password_new_user['fg'] == "grey":
        password_new_user.delete('0', "end")  # delete all the text in the entry
        password_new_user.config(fg='black', font='Helvetica 14 bold')


def password_entry_check_new_user2(event):
    global password_new_user
    if not password_new_user.get():
        password_new_user.config(fg='grey', font='Helvetica 12')
        password_new_user.insert("0", "Please Enter Your Password Here...")


# new user screen
def new_user(background, username_entry="", password_entry=""):
    global background_image
    global username_new_user, password_new_user

    for widget in Root.winfo_children():
        widget.destroy()

    Root.title("New User")
    background_image = ImageTk.PhotoImage(Image.open(background))
    background_label = tk.Label(Root, image=background_image)
    background_label.place(relwidth=1, relheight=1)

    button_back_to_menu = tk.Button(Root, text="back to menu", font=10,
                                    command=(lambda: main_window()))
    button_back_to_menu.place(relx=0.75, rely=0.05, relheight=0.1, relwidth=0.2)
    button_back_to_menu.config(bg="#cccccc")

    username_new_user = tk.Entry(font=40)
    username_new_user.config(fg='grey', bg="#e6e6e6", font='Helvetica 12')
    username_new_user.place(relx=0.1, rely=0.6, relheight=0.1, relwidth=0.55)  # fix
    username_new_user.bind('<FocusIn>', username_entry_check_new_user1)
    username_new_user.bind('<FocusOut>', username_entry_check_new_user2)
    username_new_user.insert("0", "Please Enter Your Username Here...")

    if username_entry and username_entry != "Please Enter Your Username Here...":
        username_new_user.delete('0', "end")  # delete all the text in the entry
        username_new_user.insert("0", username_entry)
        username_new_user.config(fg='black', font='Helvetica 14 bold')

    password_new_user = tk.Entry(font=40)
    password_new_user.config(fg='grey', bg="#e6e6e6", font='Helvetica 12')
    password_new_user.place(relx=0.1, rely=0.7, relheight=0.1, relwidth=0.55)  # fix
    password_new_user.bind('<FocusIn>', password_entry_check_new_user1)
    password_new_user.bind('<FocusOut>', password_entry_check_new_user2)
    password_new_user.insert("0", "Please Enter Your Password Here...")

    if password_entry and password_entry != "Please Enter Your Password Here...":
        password_new_user.delete('0', "end")  # delete all the text in the entry
        password_new_user.insert("0", password_entry)
        password_new_user.config(fg='black', font='Helvetica 14 bold')

    username_new_user.bind('<Down>', lambda event: password_new_user.focus_set())
    password_new_user.bind('<Up>', lambda event: username_new_user.focus_set())

    secret = tk.Button(Root, text="hide", font=10,
                              command=(lambda: hide_password(password_new_user)))
    secret.place(relx=0.57, rely=0.7, relheight=0.1, relwidth=0.08)
    secret.config(bg="#cccccc")

    button_confirm = tk.Button(Root, text="Confirm", font=10,
                command=(lambda: send_data_to_server(["request", "create_new_user", username_new_user.get(), password_new_user.get()])))
    button_confirm.place(relx=0.3, rely=0.85, relheight=0.13, relwidth=0.4)
    button_confirm.config(bg="#cccccc")

    Root.bind("<Return>",
              lambda event: send_data_to_server(["request", "create_new_user", username_new_user.get(), password_new_user.get()]))
    Root.protocol('WM_DELETE_WINDOW', lambda: close_window())


def username_entry_check_login1(event):
    global username_login
    if username_login['fg'] == "grey":
        username_login.delete('0', "end")  # delete all the text in the entry
        username_login.config(fg='black', font='Helvetica 14 bold')


def username_entry_check_login2(event):
    global username_login
    if not username_login.get():
        username_login.config(fg='grey', font='Helvetica 12')
        username_login.insert("0", "Please Enter Your Username Here...")


def password_entry_check_login1(event):
    global password_login
    if password_login['fg'] == "grey":
        password_login.delete('0', "end")  # delete all the text in the entry
        password_login.config(fg='black', font='Helvetica 14 bold')


def password_entry_check_login2(event):
    global password_login
    if not password_login.get():
        password_login.config(fg='grey', font='Helvetica 12')
        password_login.insert("0", "Please Enter Your Password Here...")


# login screen
def login(background, username_entry="", password_entry=""):
    global background_image
    global username_login, password_login

    for widget in Root.winfo_children():
        widget.destroy()

    Root.title("Exists User")
    background_image = ImageTk.PhotoImage(Image.open(background))
    background_label = tk.Label(Root, image=background_image)
    background_label.place(relwidth=1, relheight=1)

    button_back_to_menu = tk.Button(Root, text="back to menu", font=10,
                                    command=(lambda: main_window()))
    button_back_to_menu.place(relx=0.75, rely=0.05, relheight=0.1, relwidth=0.2)
    button_back_to_menu.config(bg="#cccccc")

    username_login = tk.Entry(font=40)
    username_login.config(fg='grey', bg="#e6e6e6", font='Helvetica 12')
    username_login.place(relx=0.1, rely=0.6, relheight=0.1, relwidth=0.55)  # fix
    username_login.bind('<FocusIn>', username_entry_check_login1)
    username_login.bind('<FocusOut>', username_entry_check_login2)
    username_login.insert("0", "Please Enter Your Username Here...")

    if username_entry and username_entry != "Please Enter Your Username Here...":
        username_login.delete('0', "end")  # delete all the text in the entry
        username_login.insert("0", username_entry)
        username_login.config(fg='black', font='Helvetica 14 bold')

    password_login = tk.Entry(font=40)
    password_login.config(fg='grey', bg="#e6e6e6", font='Helvetica 12')
    password_login.place(relx=0.1, rely=0.7, relheight=0.1, relwidth=0.55)  # fix
    password_login.bind('<FocusIn>', password_entry_check_login1)
    password_login.bind('<FocusOut>', password_entry_check_login2)
    password_login.insert("0", "Please Enter Your Password Here...")

    if password_entry and password_entry != "Please Enter Your Password Here...":
        password_login.delete('0', "end")  # delete all the text in the entry
        password_login.insert("0", password_entry)
        password_login.config(fg='black', font='Helvetica 14 bold')

    username_login.bind('<Down>', lambda event: password_login.focus_set())
    password_login.bind('<Up>', lambda event: username_login.focus_set())

    secret = tk.Button(Root, text="hide", font=10,
                       command=(lambda: hide_password(password_login)))
    secret.place(relx=0.57, rely=0.7, relheight=0.1, relwidth=0.08)
    secret.config(bg="#cccccc")

    button_confirm = tk.Button(Root, text="Confirm", font=10,
                    command=(lambda: send_data_to_server(["request", "login_to_account", username_login.get(), password_login.get()])))
    button_confirm.place(relx=0.3, rely=0.85, relheight=0.13, relwidth=0.4)
    button_confirm.config(bg="#cccccc")

    Root.bind("<Return>",
              lambda event: send_data_to_server(["request", "login_to_account", username_login.get(), password_login.get()]))
    Root.protocol('WM_DELETE_WINDOW', lambda: close_window())


# check the following:
# username - 1.username not in use already 2.username must be at list 4 letters
# password - 1.password must be at list 4 letters
def check(data, username, password):
    print("Client received data: ", handle_message(data))
    if data[0] == "confirmed":
        if data[1] == "exit":
            return
        if data[1] == "public_key_sent":
            global Public_key
            Public_key = [int(data[3]), int(data[4])]

        if data[1] == "new_user_created":
            main_window(background=Register_User_B)
        if data[1] == "login":
            how_to_use(How_To_Use_B, username)
        if data[1] == "person_inserted":
            persons_window(username, face=True)
        if data[1] == "person in this image":
            insert_correct_images(username, data[2], data[3])
        if data[1] == "no more images found":
            face_process(username, person_search=False)  # this time there are images in correct_images
        if data[1] == "here_are_the_history_folders":
            folders = data[2].split(", ")
            history_window(username, folders=folders)
        if data[1] == "insert_image_to_history":
            folder = data[2]
            sub_folder = data[3]
            name_of_image = data[4]
            image_data = base64.b64decode(data[5])
            insert_history_images(username, folder, sub_folder, name_of_image, image_data)
        if data[1] == "no more history files":
            history_window(username, done=True)

    if data[0] == "error":
        # create account
        if data[1] == "no_username":
            new_user(No_UserName_B, password_entry=password)
            return
        if data[1] == "no_password":
            new_user(No_Password_B, username_entry=username)
            return
        if data[1] == "username_too_short":
            new_user(Short_Username_B, username_entry=username, password_entry=password)
            return
        if data[1] == "password_too_short":
            new_user(Short_Password_B, username_entry=username, password_entry=password)
            return
        if data[1] == "username_exists":
            new_user(Username_Already_In_Use_B, username_entry=username, password_entry=password)
            return
        # login into account
        if data[1] == "username_not_matching_the_password":
            login(background=Unknown_User_B, username_entry=username, password_entry=password)
        if data[1] == "account_is_already_being_use":
            print("Don't forget to add this error screen in the future (trying to enter to account in parallel)")
            login(background=Account_In_Use_B, username_entry=username, password_entry=password)


def insert_correct_images(username, name, data):
    global correct_images

    client_path = os.path.join(Client_Path_Images + "-" + username,
                               str(datetime.datetime.now()).replace(':', ';').replace('.', ','))

    os.makedirs(client_path)
    image_path = os.path.join(client_path, name)
    plt.savefig(image_path)

    created_file = open(image_path, "wb")
    created_file.write(base64.b64decode(data))
    created_file.close()

    correct_images.append(image_path)

    # to make the client be ready to receive
    send_data_to_server(["ok", "got the person - ready for more", username, "no password"])


# if the user is in public, he can hide whats is written on the password entry.
def hide_password(password):
    global Hide
    if Hide == "*":
        Hide = ""
    else:
        Hide = "*"
    password.config(show=Hide)


def how_to_use(background, username):
    global background_image
    for widget in Root.winfo_children():
        widget.destroy()

    image = Image.open(background)
    width, height = image.size
    my_canvas = tk.Canvas(Root, width=width, height=height)
    my_canvas.pack()

    Root.title("How To Use")
    background_image = ImageTk.PhotoImage(image)
    background_label = tk.Label(Root, image=background_image)
    background_label.place(relwidth=1, relheight=1)

    button_next_to_inputs = tk.Button(Root, text="next", font=10, command=(lambda: input_window(username)))
    button_next_to_inputs.place(relx=0.75, rely=0.87, relheight=0.1, relwidth=0.2)
    button_next_to_inputs.config(bg="#cccccc")
    Root.bind("<Return>",
              lambda event: input_window(username))
    Root.protocol('WM_DELETE_WINDOW', lambda: close_window(username=username))


def close_window(username=""):
    send_data_to_server(["request", "exit", username])  # an empty string can't be username
    Client.close()
    Root.quit()
    Root.destroy()


def input_window(username, background=Inputs_B, person=False, gallery=False):
    global background_image
    for widget in Root.winfo_children():
        widget.destroy()

    image = Image.open(background)
    width, height = image.size
    my_canvas = tk.Canvas(Root, width=width, height=height)
    my_canvas.pack()

    Root.title("Input Window")
    background_image = ImageTk.PhotoImage(image)
    background_label = tk.Label(Root, image=background_image)
    background_label.place(relwidth=1, relheight=1)

    if not person:
        button_person = tk.Button(Root, text="Person", font=10, command=(lambda: persons_window(username)))
        button_person.place(relx=0.22, rely=0.32, relheight=0.12, relwidth=0.5)
        button_person.config(bg="#cccccc")

    if person:
        button_person = tk.Button(Root, text="Person - done", font=10, command=None)
        button_person.place(relx=0.22, rely=0.32, relheight=0.12, relwidth=0.5)
        button_person.config(bg="#4FFF33")

        button_gallery = tk.Button(Root, text="Gallery", font=10,
                                   command=(lambda: gallery_window(username)))
        button_gallery.place(relx=0.22, rely=0.47, relheight=0.12, relwidth=0.5)
        button_gallery.config(bg="#cccccc")

    if gallery:
        button_person = tk.Button(Root, text="Person - done", font=10, command=None)
        button_person.place(relx=0.22, rely=0.32, relheight=0.12, relwidth=0.5)
        button_person.config(bg="#4FFF33")

        button_gallery = tk.Button(Root, text="Gallery - done", font=10, command=None)
        button_gallery.place(relx=0.22, rely=0.47, relheight=0.12, relwidth=0.5)
        button_gallery.config(bg="#4FFF33")

        button_next_to_process = tk.Button(Root, text="next to process", font=10,
                                          command=(lambda: face_process(username)))
        button_next_to_process.place(relx=0.75, rely=0.87, relheight=0.1, relwidth=0.2)
        button_next_to_process.config(bg="#cccccc")

    restart = tk.Button(Root, text="restart inputs", font=10, command=(lambda: input_window(username)))
    restart.place(relx=0.05, rely=0.87, relheight=0.1, relwidth=0.2)
    restart.config(bg="#cccccc")

    Root.bind("<Return>", lambda event: None)  # changing the event when pressing enter.

    Root.protocol('WM_DELETE_WINDOW', lambda: close_window(username=username))


def select_object(username, person=False, history=False):
    if person:  # select a person
        global Person_Path
        Person_Path = filedialog.askopenfilename(filetypes=file_types)
        persons_window(username)
    if history:  # select an object
        start_path = Client_Path_History + "-" + username
        path = filedialog.askopenfilename(filetypes=file_types, initialdir=start_path)
        history_window(username, done=True, path=path)


def persons_window(username, background=Detection_Faces_B, face=False):
    global background_image, Person_Path
    for widget in Root.winfo_children():
        widget.destroy()

    image = Image.open(background)
    width, height = image.size
    my_canvas = tk.Canvas(Root, width=width, height=height)
    my_canvas.pack()

    Root.title("Person Window")
    background_image = ImageTk.PhotoImage(image)
    background_label = tk.Label(Root, image=background_image)
    background_label.place(relwidth=1, relheight=1)

    select_image = tk.Button(Root, text="Select Image", font=10,
                                       command=(lambda: select_object(username, person=True)))
    select_image.place(relx=0.05, rely=0.87, relheight=0.1, relwidth=0.2)
    select_image.config(bg="#cccccc")

    try:  # if the program gets closed in the middle of a process
        if Person_Path:
            client_path = os.path.join(Client_Path_Images + "-" + username,
                                        str(datetime.datetime.now()).replace(':', ';').replace('.', ','))
            os.makedirs(client_path)
            image_path = os.path.join(client_path, ntpath.basename(Person_Path).replace(".jpg", ".png"))
            plt.savefig(image_path)
            img2 = Image.open(Person_Path)
            im_resize = img2.resize((500, 300), Image.ANTIALIAS)
            im_resize.save(image_path)

            Picture(background_label, image_path).pack(fill="both", expand=True, anchor='nw')
            if os.path.isdir(Client_Path_Images + "-" + username):
                shutil.rmtree(Client_Path_Images + "-" + username)

        if Person_Path and not face:
                select_image.destroy()

                with open(Person_Path, "rb") as f:
                    data = f.read()
                f.close()

                # checks if the image has one face. if it does, he saves it. else he returns an error message.
                send_data_to_server(["request", "insert_person_image", username,
                                     base64.b64encode(data), ntpath.basename(Person_Path).replace(".jpg", ".png")])

        if Person_Path and face:
            button_next_to_inputs = tk.Button(Root, text="next", font=10,
                                              command=(lambda: input_window(username, person=True)))
            button_next_to_inputs.place(relx=0.75, rely=0.87, relheight=0.1, relwidth=0.2)
            button_next_to_inputs.config(bg="#cccccc")
    except tk.TclError:
        return

    Person_Path = ''
    change_image = tk.Button(Root, text="Change Image", font=10,
                             command=(lambda: select_object(username, True)))
    change_image.place(relx=0.05, rely=0.87, relheight=0.1, relwidth=0.2)
    change_image.config(bg="#cccccc")

    Root.protocol('WM_DELETE_WINDOW', lambda: close_window(username=username))


def select_folder(username):
    folder_selected = filedialog.askdirectory()
    gallery_window(username, path=folder_selected)


def gallery_window(username, background=Gallery_B, path=''):
    global background_image, image_counter, images, types
    for widget in Root.winfo_children():
        widget.destroy()

    image = Image.open(background)
    width, height = image.size
    my_canvas = tk.Canvas(Root, width=width, height=height)
    my_canvas.pack()

    Root.title("Gallery Window")
    background_image = ImageTk.PhotoImage(image)
    background_label = tk.Label(Root, image=background_image)
    background_label.place(relwidth=1, relheight=1)

    if not path:
        select_image = tk.Button(Root, text="Select Gallery", font=10,
                                 command=(lambda: select_folder(username)))
        select_image.place(relx=0.75, rely=0.87, relheight=0.1, relwidth=0.2)
        select_image.config(bg="#cccccc")

    if path:
        try:  # if the program gets closed in the middle of a process
            find_file_type(path, types)

            send_data_to_server(["request", "insert_gallery_folder", username, ntpath.basename(path)])

            legal_images = []

            progress_var = DoubleVar()
            progressbar = ttk.Progressbar(Root, variable=progress_var, maximum=len(images))
            progressbar.pack(fill='x', expand=1)

            image_checked = 1

            for path in images:
                with open(path, "rb") as f:
                    data = f.read()
                f.close()

                send_data_to_server(["request", "insert_person_to_gallery", username,
                                     base64.b64encode(data), ntpath.basename(path).replace(".jpg", ".png")])

                client_path = os.path.join(Client_Path_Images + "-" + username,
                                           str(datetime.datetime.now()).replace(':', ';').replace('.', ','))

                os.makedirs(client_path)
                image_path = os.path.join(client_path, ntpath.basename(path).replace(".jpg", ".png"))
                plt.savefig(image_path)
                img2 = Image.open(path)
                im_resize = img2.resize((500, 300), Image.ANTIALIAS)
                im_resize.save(image_path)
                legal_images.append(image_path)
                progress_var.set(image_checked)
                image_checked = image_checked + 1
                Root.update_idletasks()
                time.sleep(0.02)
                Root.update()

            progressbar.destroy()

            GalleryScroll(background_label, legal_images).pack(fill="both", expand=True, anchor='nw')
            if os.path.isdir(Client_Path_Images + "-" + username):
                shutil.rmtree(Client_Path_Images + "-" + username)
            images = []

        except tk.TclError:
            return

        button_next_to_inputs = tk.Button(Root, text="next", font=10,
                                          command=(lambda: input_window(username, gallery=True)))
        button_next_to_inputs.place(relx=0.75, rely=0.87, relheight=0.1, relwidth=0.2)
        button_next_to_inputs.config(bg="#cccccc")

    Root.protocol('WM_DELETE_WINDOW', lambda: close_window(username=username))


def waiting_window(username, background=Wait_B):
    global background_image
    for widget in Root.winfo_children():
        widget.destroy()

    image = Image.open(background)
    width, height = image.size
    my_canvas = tk.Canvas(Root, width=width, height=height)
    my_canvas.pack()

    Root.title("Waiting Window")
    background_image = ImageTk.PhotoImage(image)
    background_label = tk.Label(Root, image=background_image)
    background_label.place(relwidth=1, relheight=1)

    face_process(username)

    Root.protocol('WM_DELETE_WINDOW', lambda: close_window(username=username))


def face_process(username, background=Blank_B, person_search=True):
    global background_image, image_counter, correct_images, types
    for widget in Root.winfo_children():
        widget.destroy()

    image = Image.open(background)
    width, height = image.size
    my_canvas = tk.Canvas(Root, width=width, height=height)
    my_canvas.pack()

    Root.title("Correct Images")
    background_image = ImageTk.PhotoImage(image)
    background_label = tk.Label(Root, image=background_image)
    background_label.place(relwidth=1, relheight=1)

    if person_search:
        send_data_to_server(["request", "find_the_person", username, "no_password"])

    else:
        legal_images = []

        progress_var = DoubleVar()

        progressbar = ttk.Progressbar(Root, variable=progress_var, maximum=len(correct_images))
        progressbar.pack(fill='x', expand=1)

        image_checked = 1
        try:  # if the program gets closed in the middle of a process
            for path in correct_images:

                client_path = os.path.join(Client_Path_Images + "-" + username,
                                           str(datetime.datetime.now()).replace(':', ';').replace('.', ','))

                os.makedirs(client_path)
                image_path = os.path.join(client_path, ntpath.basename(path).replace(".jpg", ".png"))
                plt.savefig(image_path)
                img2 = Image.open(path)
                im_resize = img2.resize((500, 300), Image.ANTIALIAS)
                im_resize.save(image_path)
                legal_images.append(image_path)
                progress_var.set(image_checked)
                image_checked = image_checked + 1
                Root.update_idletasks()
                time.sleep(0.02)
                Root.update()

            progressbar.destroy()

            GalleryScroll(background_label, legal_images).pack(fill="both", expand=True, anchor='nw')
            if os.path.isdir(Client_Path_Images + "-" + username):
                shutil.rmtree(Client_Path_Images + "-" + username)
            correct_images = []

        except tk.TclError:
            return
        button_next_to_history = tk.Button(Root, text="Next To History", font=10,
                                          command=(lambda: history_window(username)))
        button_next_to_history.place(relx=0.75, rely=0.87, relheight=0.1, relwidth=0.2)
        button_next_to_history.config(bg="#cccccc")

        button_redo_the_process = tk.Button(Root, text="Redo The Process", font=10,
                                           command=(lambda: input_window(username)))
        button_redo_the_process.place(relx=0.45, rely=0.87, relheight=0.1, relwidth=0.2)
        button_redo_the_process.config(bg="#cccccc")

    Root.protocol('WM_DELETE_WINDOW', lambda: close_window(username=username))


def find_file_type(path, types):
    global image_counter, images
    try:
        dirs = os.listdir(path)
        for dir in dirs:
            find_file_type(path + "\\" + dir, types)
    except:
        for type in types:
            if path.endswith(type):
                images.append(path)
                image_counter = image_counter + 1


def send_symmetrical_key_to_server():  # Bob
    m = generate_symmetrical_key(Symmetrical_Key, min(Public_key[1], 150000))
    e = Public_key[0]
    n = Public_key[1]
    blah2 = pow(m, e)
    c = blah2 % n
    return c  # encoded message that only server can encode


def generate_symmetrical_key(min_value, max_value):
    global Symmetrical_Key
    Symmetrical_Key = random.randint(min_value, max_value)
    print("symmetrical key: ", Symmetrical_Key)
    return Symmetrical_Key


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


def history_window(username, background=History_B, folders=[], image="", done=False, path="no_path"):
    global background_image, image_counter, correct_images, types
    for widget in Root.winfo_children():
        widget.destroy()

    image = Image.open(background)
    width, height = image.size
    my_canvas = tk.Canvas(Root, width=width, height=height)
    my_canvas.pack()

    Root.title("History")
    background_image = ImageTk.PhotoImage(image)
    background_label = tk.Label(Root, image=background_image)
    background_label.place(relwidth=1, relheight=1)

    if not done:
        if not os.path.isdir(Client_Path_History + "-" + username):  # create history path if it was not already created
            os.makedirs(Client_Path_History + "-" + username)

        if not folders:  # not got yet the history folders
            send_data_to_server(["request", "get_me_new_history_folders", username, "no_password"])

        if folders:
            for folder in folders:
                folder = folder.replace("'", "")
                history_folder = os.path.join(Client_Path_History + "-" + username, folder)
                os.makedirs(history_folder)
                person_path = os.path.join(history_folder, "Person")
                gallery_path = os.path.join(history_folder, "Gallery")
                correct_person_path = os.path.join(history_folder, "Correct")
                os.makedirs(person_path)
                os.makedirs(gallery_path)
                os.makedirs(correct_person_path)


            send_data_to_server(["request", "get_me_images_in_folders", username, "no_password"])

    else:
        if path == "no_path":  # the user is not have to pick a path.
            select_object(username, history=True)
        elif path:
            client_path = os.path.join(Client_Path_Images + "-" + username,
                                       str(datetime.datetime.now()).replace(':', ';').replace('.', ','))
            os.makedirs(client_path)
            image_path = os.path.join(client_path, ntpath.basename(path).replace(".jpg", ".png"))
            plt.savefig(image_path)
            img2 = Image.open(path)
            im_resize = img2.resize((500, 300), Image.ANTIALIAS)
            im_resize.save(image_path)

            Picture(background_label, image_path).pack(fill="both", expand=True, anchor='nw')
            if os.path.isdir(Client_Path_Images + "-" + username):
                shutil.rmtree(Client_Path_Images + "-" + username)

    button_reshow_history = tk.Button(Root, text="Reshow History", font=10,
                                       command=(lambda: history_window(username, done=True)))
    button_reshow_history.place(relx=0.05, rely=0.87, relheight=0.1, relwidth=0.2)
    button_reshow_history.config(bg="#cccccc")

    button_redo_the_process = tk.Button(Root, text="Redo The Process", font=10,
                                        command=(lambda: input_window(username)))
    button_redo_the_process.place(relx=0.40, rely=0.87, relheight=0.1, relwidth=0.2)
    button_redo_the_process.config(bg="#cccccc")

    button_exit = tk.Button(Root, text="Exit The App", font=10,
                                       command=(lambda: close_window(username=username)))
    button_exit.place(relx=0.75, rely=0.87, relheight=0.1, relwidth=0.2)
    button_exit.config(bg="#cccccc")

    Root.protocol('WM_DELETE_WINDOW', lambda: close_window(username=username))


def insert_history_images(username, folder, sub_folder, name_of_image, image_data):
    history_image_path = os.path.join(Client_Path_History + "-" + username, folder, sub_folder, name_of_image)

    plt.savefig(history_image_path)
    created_file = open(history_image_path, "wb")
    created_file.write(image_data)
    created_file.close()

    # to make the client be ready to receive
    send_data_to_server(["ok", "got the person - ready for more", username, "no password"])


# gets a public key
send_data_to_server(["request", "get_public_key", "no_username", "no_password"])
# encoding the message, can't encode value that is greater than n
# (and n has a limit to be not huge, because i want the program to run fast)
# and my encryption can't encrypt value greater than 150,000
send_data_to_server(["request", "create_a_symmetrical_key", "no_username", "no_password",
                     str(send_symmetrical_key_to_server())], use_symmetrical_key=False)

# activating the client
main_window()
