import logging
from datetime import datetime
from os import makedirs, environ

import bcrypt
from appdirs import user_data_dir
from peewee import *

path = user_data_dir("PenguChatServer")
environ['KIVY_NO_ENV_CONFIG'] = '1'
environ["KCFG_KIVY_LOG_LEVEL"] = "debug"
environ["KCFG_KIVY_LOG_DIR"] = path + '/PenguChat/Logs'

FORMAT = '%(asctime)-15s %(message)s'
logging.basicConfig(format=FORMAT, level=logging.INFO)

db = SqliteDatabase(path + '/Users.db')


class User(Model):
    username = CharField(100)
    password_hash = TextField()
    password_salt = TextField()
    last_login = DateTimeField()

    class Meta:
        database = db


class MessageCache(Model):
    sender = CharField(100)
    destination = CharField(100)
    command = CharField(100)
    content = BlobField(null=True)
    timestamp = DateTimeField()
    is_key = BooleanField(default=False)
    isfile = BooleanField()
    filename = TextField()

    class Meta:
        database = db


def add_message_to_cache(packet):
    try:
        content = packet['content']
    except KeyError:
        content = ""

    try:
        filename = packet['filename']
    except KeyError:
        filename = ""

    if not isinstance(content, bytes):
        content = str(content).encode()

    MessageCache(
        sender=packet['sender'],
        destination=packet['destination'],
        content=content,
        timestamp=packet['timestamp'],
        command=packet['command'],
        isfile=packet['isfile'],
        filename=filename
    ).save()


def get_cached_messages_for_user(username):
    query = MessageCache.select().where(MessageCache.destination == username)
    messages = []
    for i in query:
        messages.append(i.__data__)
        i.delete_instance()
    db.commit()
    return messages


def add_user(username, pwd, salt):
    try:
        User.get(User.username == username)
    except User.DoesNotExist:
        new_user = User(username=username, password_hash=pwd, password_salt=salt, last_login=datetime.now())
        new_user.save()
        return True
    else:
        return False


def login(username, password):
    if len(username) == 0 or len(password) == 0:
        return False
    try:
        query = User.get(User.username == username)
    except User.DoesNotExist:
        logging.warning("User not found!")
        return False
    else:
        salt = get_salt_for_user(username)
        password = bcrypt.hashpw(password, salt)
        encrypted = query.password_hash.encode()
        if password == encrypted:
            query.last_login = datetime.now()
            query.save()
            return True
        else:
            return False


def delete_user(username, password):
    if login(username, password):
        User.delete().where(User.username == username).execute()
        return True
    return False


def get_salt_for_user(username):
    try:
        query = User.get(User.username == username)
    except User.DoesNotExist:
        return False
    else:
        return query.password_salt.encode()


try:
    db.create_tables([User, MessageCache])
except OperationalError as t:
    try:
        makedirs(path)
    except FileExistsError:
        pass
    try:
        open(path + '/Users.db', 'r')
    except FileNotFoundError:
        logging.warning("Database file missing, re-creating. ")
        with open(path + '/Users.db', "w+"):
            pass
    db.create_tables([User, MessageCache])
