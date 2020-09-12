import sqlite3

db = sqlite3.connect('db.sqlite3')
cursor = db.cursor()
cursor.execute("SELECT * from sqlite_sequence")
print(cursor.fetchall())