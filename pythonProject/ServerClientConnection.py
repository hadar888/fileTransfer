from enum import Enum


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
    CRC_OK = 1104
    CRC_NOT_OK_RESEND = 1105
    CRC_NOT_OK_ABORT = 1106


class MsgTypes(Enum):
    REGISTER_OK = 2100
    REGISTER_FAILD = 2101
    SEND_AES_KEY = 2102
    SEND_CRC = 2103
    GOT_REQUEST = 2104


def get_client_msg(conn):
    try:
        data = conn.recv(1024)
        client_id = data[0:16:1]
        version = int.from_bytes(data[16:17:1], byteorder='little', signed=False)
        code = int.from_bytes(data[17:19:1], byteorder='little', signed=False)
        payload_size = int.from_bytes(data[19:23:1], byteorder='little', signed=False)
        payload = data[23:23 + payload_size:1]
        return {"ClientId": client_id, "Version": version, "Code": code, "PayloadSize": payload_size}, payload
    except Exception as error:
        print("ERROR: faild to get msg form client, format error\n", error)
        return ""


def send_msg_to_client(conn, reply):
    try:
        conn.sendall(reply)
    except Exception as error:
        print("Server error: fail to send msg to client\n", error)


def get_field_from_payload(payload, start_index, end_index, is_string=False):
    value = payload[start_index:end_index:1]
    if is_string:
        value = value.decode("utf-8").rstrip('\x00')
    return value
