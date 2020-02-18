from tkinter import DoubleVar, filedialog, ttk   #StringVar
import socket
import pickle
from Client.Encryption_And_Decryption import *
import random
import base64
import ntpath
import matplotlib.pyplot as plt
import datetime
from PIL import Image, ImageTk
import time
# connection setting:
from Client.Communication_Settings import *
from Client.Face_Detection_And_Comparison import *
from Client.Handle_Images import *
import shutil


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
Client_Path_Images = "C:\\Detection_App"
file_types = [("Image File", '.jpg'), ("Image File", '.png')]
types = ['.jpg', '.png']
username_new_user = None
password_new_user = None
username_login = None
password_login = None

# communication with the server
def send_data_to_server(data, client=Client, use_symmetrical_key=True, name_of_file=''):
    global Symmetrical_Keys
    print("Client sent: ", data)
    if use_symmetrical_key:  # Encrypt
        msg_decrypted = pickle.dumps(encryption(data, Symmetrical_Key))
    else:  # A message to get a public key, encrypted without a public key - RSA
        msg_decrypted = pickle.dumps(encryption(data))
    packet = add_zeros(str(len(msg_decrypted))).encode() + msg_decrypted
    client.send(packet)

    if len(data) > 3:
        size = int(client.recv(Max_Data_Size))
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
    print("Client received data: ", data)
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

        button_next_to_process = tk.Button(Root, text="next", font=10,
                                          command=(lambda: print("next to process")))
        button_next_to_process.place(relx=0.75, rely=0.87, relheight=0.1, relwidth=0.2)
        button_next_to_process.config(bg="#cccccc")

    restart = tk.Button(Root, text="restart inputs", font=10, command=(lambda: input_window(username)))
    restart.place(relx=0.05, rely=0.87, relheight=0.1, relwidth=0.2)
    restart.config(bg="#cccccc")

    Root.protocol('WM_DELETE_WINDOW', lambda: close_window(username=username))


def select_person(username):
    path = filedialog.askopenfilename(filetypes=file_types)
    persons_window(username, path=path)


def persons_window(username, background=Detection_Faces_B, path=''):
    global background_image
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
                                       command=(lambda: select_person(username)))
    select_image.place(relx=0.05, rely=0.87, relheight=0.1, relwidth=0.2)
    select_image.config(bg="#cccccc")

    if path:
        select_image.destroy()
        face, msg = is_face(path)
        if not face:
            persons_window(username)  # add background
            print(msg)
            print("don't forget to add this background which you can't input an image without faces.")
        else:
            with open(path, "rb") as f:
                data = f.read()
            f.close()

            send_data_to_server(["request", "insert_person_image", username,
                            base64.b64encode(data), ntpath.basename(path).replace(".jpg", ".png")], name_of_file=path)

            client_path = os.path.join(Client_Path_Images,
                                       str(datetime.datetime.now()).replace(':', ';').replace('.', ','))
            os.makedirs(client_path)
            image_path = os.path.join(client_path, ntpath.basename(path).replace(".jpg", ".png"))
            plt.savefig(image_path)
            img2 = Image.open(path)
            im_resize = img2.resize((500, 300), Image.ANTIALIAS)
            im_resize.save(image_path)

            Picture(background_label, image_path).pack(fill="both", expand=True, anchor='nw')
            shutil.rmtree(Client_Path_Images)

            change_image = tk.Button(Root, text="Change Image", font=10,
                                     command=(lambda: select_person(username)))
            change_image.place(relx=0.05, rely=0.87, relheight=0.1, relwidth=0.2)
            change_image.config(bg="#cccccc")

            button_next_to_inputs = tk.Button(Root, text="next", font=10,
                                              command=(lambda: input_window(username, person=True)))
            button_next_to_inputs.place(relx=0.75, rely=0.87, relheight=0.1, relwidth=0.2)
            button_next_to_inputs.config(bg="#cccccc")

            Root.bind("<Return>",
                      lambda event: input_window(username, person=True))

    Root.protocol('WM_DELETE_WINDOW', lambda: close_window(username=username))


def select_folder(username):
    folder_selected = filedialog.askdirectory()
    gallery_window(username, path=folder_selected)


def gallery_window(username, background=Gallery_B, path=''):
    global background_image
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

    select_image = tk.Button(Root, text="Select Gallery", font=10,
                             command=(lambda: select_folder(username)))
    select_image.place(relx=0.75, rely=0.87, relheight=0.1, relwidth=0.2)
    select_image.config(bg="#cccccc")

    if path:
        global image_counter, images, types
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
                            base64.b64encode(data), ntpath.basename(path).replace(".jpg", ".png")], name_of_file=path)

            client_path = os.path.join(Client_Path_Images,
                                       str(datetime.datetime.now()).replace(':', ';').replace('.', ','))

            background_label.config(text="Change Gallery")
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
        shutil.rmtree(Client_Path_Images)

        button_next_to_inputs = tk.Button(Root, text="next", font=10,
                                          command=(lambda: input_window(username, gallery=True)))
        button_next_to_inputs.place(relx=0.75, rely=0.87, relheight=0.1, relwidth=0.2)
        button_next_to_inputs.config(bg="#cccccc")

        Root.bind("<Return>",
                  lambda event: input_window(username, gallery=True))

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
        print("size too big, add this screen to the images backgrounds")


# gets a public key
send_data_to_server(["request", "get_public_key", "no_username", "no_password"])
# encoding the message, can't encode value that is greater than n
# (and n has a limit to be not huge, because i want the program to run fast)
# and my encryption can't encrypt value greater than 150,000
send_data_to_server(["request", "create_a_symmetrical_key", "no_username", "no_password",
                     str(send_symmetrical_key_to_server())], use_symmetrical_key=False)

# activating the client
main_window()
