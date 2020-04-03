import sqlite3
import os
import psutil

DB_Current_Path = r"C:\Users\almog\AppData\Local\Programs\Python\Python37\programming\Detection_app\Server\DB"
Current_Working_Directory = r'C:\Users\almog\AppData\Local\Programs\Python\Python37\programming\Detection_app\Server\Run_Server.py'
Db_Path = r"C:\Users\almog\AppData\Local\Programs\Python\Python37\programming\Detection_app\Server\DB\Users.db"


class Database:
    def __init__(self, db_location=Db_Path):
        self.conn = sqlite3.connect(db_location)
        self.cur = self.conn.cursor()
        self.cur.execute("CREATE TABLE IF NOT EXISTS Info (username text, password text, path text, active text, history_folders text)")
        self.conn.commit()

    def fetch(self):
        self.cur.execute("SELECT * FROM Info")
        rows = self.cur.fetchall()
        return rows

    def insert(self, username, password):
        self.cur.execute("SELECT * FROM Info WHERE username=(?)", (username,))
        if self.cur.fetchone() is not None:
                return False

        self.cur.execute("INSERT INTO Info VALUES (? , ?, ?, ?, ?)",
                            (username, password, self.generate_path(username), "n", ""))

        self.conn.commit()
        return True

    def exists(self, username, password):
        self.cur.execute("SELECT username FROM Info")
        usernames = self.cur.fetchall()
        self.cur.execute("SELECT password FROM Info")
        passwords = self.cur.fetchall()
        for i in range(len(usernames)):
            if usernames[i][0] == username and passwords[i][0] == password:
                return True
        return False

    def generate_path(self, username):
        user_path = DB_Current_Path + "\\" + username
        os.makedirs(user_path)
        return user_path

    def active_user(self, username):
        self.cur.execute("SELECT username FROM Info")
        usernames = self.cur.fetchall()
        self.cur.execute("SELECT active FROM Info")
        actives = self.cur.fetchall()
        for i in range(len(usernames)):
            if usernames[i][0] == username and actives[i][0] == "y":
                return False
        self.cur.execute("UPDATE Info SET active = ? WHERE username = ?",
                         ("y", username))
        self.conn.commit()
        return True

    def unactive_user(self, username):
        self.cur.execute("SELECT username FROM Info")
        usernames = self.cur.fetchall()
        self.cur.execute("SELECT active FROM Info")
        actives = self.cur.fetchall()
        for i in range(len(usernames)):
            if usernames[i][0] == username and actives[i][0] == "y":
                self.cur.execute("UPDATE Info SET active = ? WHERE username = ?",
                                 ("n", username))
                self.conn.commit()
        return True

    def remove_user(self, username):
        self.cur.execute("DELETE FROM Info WHERE username=?", (username,))
        self.conn.commit()

    def update_user(self, username, password):
        self.cur.execute("UPDATE Info SET username = ?, password = ?",
                         (username, password))
        self.conn.commit()

    def unactive_all(self):
        self.cur.executemany("UPDATE Info SET active = ?", ("n"))
        self.conn.commit()

    def running(self):
        for q in psutil.process_iter():
            if q.name() == 'python':
                print(q.cmdline())
                if len(q.cmdline()) > 1 and Current_Working_Directory in q.cmdline()[1]:
                    return True
        return False

    def get_user_path(self, username):
        self.cur.execute("SELECT username FROM Info")
        usernames = self.cur.fetchall()
        self.cur.execute("SELECT path FROM Info")
        paths = self.cur.fetchall()
        for i in range(len(usernames)):
            if usernames[i][0] == username:
                return paths[i][0]
        return None

    def insert_user_history_folder(self, username, folder_name):
        self.cur.execute("SELECT username FROM Info")
        usernames = self.cur.fetchall()
        self.cur.execute("SELECT history_folders FROM Info")
        history_folders = self.cur.fetchall()
        for i in range(len(usernames)):
            if usernames[i][0] == username:
                if history_folders[i][0]:  # just to make it cleaner
                    # split with forward slash because it illegal to contain this charcter in a path.
                    all_folders = history_folders[i][0] + "\\" + folder_name
                else:
                    all_folders = folder_name
                self.cur.execute("UPDATE Info SET history_folders = ? WHERE username = ?", (all_folders, username))
                self.conn.commit()

    def get_history_folders(self, username):
        self.cur.execute("SELECT history_folders FROM Info")
        history_folders = self.cur.fetchall()
        folder_list = (history_folders[0][0]).split('\\')
        return folder_list

    def _del_(self):
        self.conn.close()


if __name__ == '__main__':

    db = Database("DB\\test.db")
    db.insert("almog_test2", "123")
    db.insert_user_history_folder("almog_test2", "Trump0")
    db.insert_user_history_folder("almog_test2", "Trump1")
    db.insert_user_history_folder("almog_test2", "Trump2")
    lst1 = db.get_history_folders("almog_test2")
    db._del_()
    lst2 = os.listdir(r'C:\Users\almog\AppData\Local\Programs\Python\Python37\programming\Detection_app\Server\DB\almog')
    print(lst1, lst2)
    result = list(set(lst2) - set(lst1))
    print(result, type(result))
