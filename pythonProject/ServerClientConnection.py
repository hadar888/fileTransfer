from enum import Enum
import json


def get_port():
    try:
        port_file = open("port.info", "r")
        port = int(port_file.read())
    except ValueError:
        print("WARNING: port value in file was not valid. Run on defualt port 1234")
        port = 1234
    except FileNotFoundError:
        print("WARNING: port file was not found. Run on defualt port 1234")
        port = 1234

    if len(str(port)) != 4:
        print("WARNING: port value in file was not valid, port can have only 4 digits. Run on defualt port 1234")
        port = 1234
    return port


class RequestType(Enum):
    REGISTER = 1100
    SEND_KEY = 2
    SEND_FILE = 3
    ABORT = 4
    CRC_OK = 5


class ReturnMsgType(Enum):
    OK = "OK"
    FAILD = "FAILD"
    SERVER_ERROR = "SERVER_ERROR"


def get_field_from_cient_msg(client_msg, filed_name):
    try:
        return client_msg[filed_name]
    except (KeyError, TypeError):
        return ""


def get_client_msg(conn):
    data = conn.recv(1024)
    try:
        text = data.decode("utf-8", errors='ignore')
        print("text: ", text)
        return json.loads(text)
    except (json.decoder.JSONDecodeError, UnicodeDecodeError):
        print("ERROR: faild to get msg form client, format error ", data)
        return ""


def get_header(msg):
    header = msg["Header"].replace("'", "\"")
    print("header: ", header)
    return json.loads(header)


def get_payload(msg):
    payload = msg["Payload"].replace("'", "\"")
    print("payload: ", payload)
    return json.loads(payload)


def send_msg_to_client(conn, reply):
    print("reply: ", reply)
    try:
        conn.sendall(reply)
    except Exception as error:
        print("server error: fail to send msg to client: ", error)
