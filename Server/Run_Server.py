from Server.Server_Functions import *
from Server.Database import Database


db = Database()
db.unactive_all()
server_socket, inputs = creating_server()

while True:
    activating_server(server_socket, inputs, db)
