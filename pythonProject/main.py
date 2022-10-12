import socket
import uuid
import dbFunctions
import ServerClientConnection
from Crypto.Cipher import AES
import zlib
import json
import os
import time
import struct
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64

clients_names = []


def register_user(request_payload, db_connection):
    username = request_payload[0:255:1].decode("utf-8")
    if username != "":  # and username not in clients_names
        user_uuid = uuid.uuid4()
        clients_names.append({"user_name": username, "uuid": user_uuid})
        try:
            dbFunctions.save_new_user_in_db(db_connection, (str(user_uuid), username, '', time.time(), ''))
        except Exception as save_user_error:
            print("WARNING: new user failed to save in the DB, ", save_user_error)
            return False
        return user_uuid
    else:
        print("WARNING: user allready exsist or was not sent")
        return False


if __name__ == '__main__':
    db_connection = dbFunctions.create_db_conection()
    if not db_connection:
        exit()
    else:
        if not dbFunctions.init_db_tables(db_connection):
            exit()
        else:
            for client_name_data in dbFunctions.get_clients_names(db_connection):
                clients_names.append(client_name_data[0])
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', ServerClientConnection.get_port()))
        s.listen()
        while True:
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                user_uuid = None
                while True:
                    try:
                        client_msg = ServerClientConnection.get_client_msg(conn)
                        client_msg_header = client_msg["Header"]
                        client_msg_payload = client_msg["Payload"]
                        request_code = client_msg_header["Code"]

                        if request_code == ServerClientConnection.RequestType.REGISTER.value:
                            user_uuid = register_user(client_msg_payload, db_connection)
                            if user_uuid:
                                ServerClientConnection.send_msg_to_client(
                                    conn, struct.pack('<BHI16s', 3, 2100, 16, user_uuid.bytes))
                            else:
                                ServerClientConnection.send_msg_to_client(
                                    conn, ServerClientConnection.ReturnMsgType.FAILD.value)
                                break

                        elif request_code == ServerClientConnection.RequestType.SEND_KEY.value:
                            username = client_msg_payload[0:255:1].decode("utf-8")
                            RAS_public_key = client_msg_payload[255:415:1]
                            user_uuid_bytes = client_msg_header["ClientId"]
                            try:
                                dbFunctions.save_user_public_key(db_connection, user_uuid, RAS_public_key)
                            except Exception as save_ras_error:
                                print("WARNING: RAS public key failed to save in the DB, ", save_ras_error)
                                break

                            AES_key = b'Sixteen byte key'
                            cipher = PKCS1_OAEP.new(RSA.importKey(RAS_public_key))
                            encrypted_AES_key = cipher.encrypt(AES_key)
                            ServerClientConnection.send_msg_to_client(conn,
                                                                      struct.pack('<BHI16s128s', 3, 2102,
                                                                                  16 + len(encrypted_AES_key),
                                                                                  user_uuid_bytes,
                                                                                  encrypted_AES_key))

                        elif request_code == ServerClientConnection.RequestType.SEND_FILE.value:
                            file_size = int.from_bytes(client_msg_payload[16:20:1], byteorder='little', signed=False)
                            file_name = client_msg_payload[20:275:1].decode("utf-8")
                            file_data = client_msg_payload[275:275 + file_size:1]

                            cipher_decrypt = AES.new(AES_key, AES.MODE_CBC, b"0000000000000000")
                            decrypt_file_data = cipher_decrypt.decrypt(file_data)
                            # TODO: fix bug for first 16 chars
                            decrypt_file_data = decrypt_file_data[16:len(decrypt_file_data):1]
                            # TODO: check if crc32 is like linux checksum
                            file_data_crc = zlib.crc32(decrypt_file_data)
                            ServerClientConnection.send_msg_to_client(conn, struct.pack('<BHI16sI255sI', 3, 2103,
                                                                                        16 + 4 + 255 + 4,
                                                                                        user_uuid_bytes,
                                                                                        file_size,
                                                                                        file_name.encode('utf-8'),
                                                                                        file_data_crc))

                        elif request_code == ServerClientConnection.RequestType.ABORT.value:
                            break

                        elif request_code == ServerClientConnection.RequestType.CRC_OK.value:
                            try:
                                file_name = ServerClientConnection.get_field_from_cient_msg(
                                    client_msg, "file_name")
                            except (json.decoder.JSONDecodeError, UnicodeDecodeError):
                                print("ERROR: faild to get file data or name form client, format error ")
                            # TODO: get userUUID
                            userUUID = "userUUID"
                            if not os.path.exists(userUUID):
                                os.mkdir(userUUID)
                            file_to_save = open(userUUID + "\\" + file_name, 'w')
                            # TODO: check if decrypt_file_data exist
                            file_to_save.write(decrypt_file_data)
                            file_to_save.close()

                        else:
                            print("WARNING: request type code is unknown or was not sent")
                            if request_code:
                                print("request_code: ", request_code)
                                print()
                            break

                    except Exception as error:
                        print("General error\n", error)
                        break

                # TODO: kill the thread
