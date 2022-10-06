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

clients_names = []


def register_user(client_register_msg, db_connection):
    request_payload = ServerClientConnection.get_payload(client_register_msg)
    username = ServerClientConnection.get_field_from_cient_msg(request_payload, "Name")
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
                        client_msg_header = ServerClientConnection.get_header(client_msg)
                        request_code = ServerClientConnection.get_field_from_cient_msg(client_msg_header, "Code")

                        if request_code == ServerClientConnection.RequestType.REGISTER.value:
                            user_uuid = register_user(client_msg, db_connection)
                            if user_uuid:
                                ServerClientConnection.send_msg_to_client(
                                    conn, struct.pack('<BHI16s', 3, 2100, 16, user_uuid.bytes))
                            else:
                                ServerClientConnection.send_msg_to_client(
                                    conn, ServerClientConnection.ReturnMsgType.FAILD.value)
                                break

                        elif request_code == ServerClientConnection.RequestType.SEND_KEY.value:
                            RAS_public_key = ServerClientConnection.get_field_from_cient_msg(
                                client_msg, "ras_public_key")
                            try:
                                dbFunctions.save_user_public_key(db_connection, user_uuid, RAS_public_key)
                            except Exception as save_ras_error:
                                print("WARNING: RAS public key failed to save in the DB, ", save_ras_error)
                                break
                            AES_public_key = b'Sixteen byte key'
                            # TODO: encrypt AES public key with RAS
                            # encrypted_AES_public_key = rsa.encrypt(AES_public_key, RAS_public_key)
                            encrypted_AES_public_key = 'encrypted_AES_public_key'
                            ServerClientConnection.send_msg_to_client(conn, encrypted_AES_public_key)

                        elif request_code == ServerClientConnection.RequestType.SEND_FILE.value:
                            file_data = ServerClientConnection.get_field_from_cient_msg(client_msg, "file")
                            # TODO: decrypt_file_data = decrypt file_data with AES_private_key
                            decrypt_file_data = file_data
                            file_data_crc = zlib.crc32(bytes(decrypt_file_data, 'utf-8'))
                            # TODO: check if crc32 is like linux checksum
                            ServerClientConnection.send_msg_to_client(conn, str(file_data_crc))

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

                    except ConnectionResetError:
                        break

                # TODO: kill the thread
