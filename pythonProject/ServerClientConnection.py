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
    SEND_KEY = 1101
    SEND_FILE = 1103
    ABORT = 4
    CRC_OK = 5


class ReturnMsgType(Enum):
    OK = "OK"
    FAILD = "FAILD"
    SERVER_ERROR = "SERVER_ERROR"


def get_client_msg(conn):
    try:
        data = conn.recv(1024)
        print("msg from client: ", data)
        client_id = data[0:16:1]
        version = int.from_bytes(data[16:17:1], byteorder='little', signed=False)
        code = int.from_bytes(data[17:19:1], byteorder='little', signed=False)
        payload_size = int.from_bytes(data[19:23:1], byteorder='little', signed=False)
        payload = data[23:23 + payload_size:1]
        return {"Header": {"ClientId": client_id, "Version": version, "Code": code, "PayloadSize": payload_size},
                "Payload": payload}
    except Exception as error:
        print("ERROR: faild to get msg form client, format error\n", error)
        return ""


def send_msg_to_client(conn, reply):
    print("reply: ", reply)
    try:
        conn.sendall(reply)
    except Exception as error:
        print("Server error: fail to send msg to client\n", error)
