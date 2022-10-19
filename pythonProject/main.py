import socket
import uuid
from dbFunctions import init_db, save_new_user_in_db, save_user_public_key, update_file_crc_verified, \
    save_new_file_data, save_user_aes_key
from ServerClientConnection import get_field_from_payload, send_msg_to_client, get_port, get_client_msg, \
    RequestType, MsgTypes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import zlib
import os
import time
import struct
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import threading

clients_names = []


def register_user(user_conn, client_msg_payload):
    new_username = get_field_from_payload(client_msg_payload, 0, 255, True)
    # TODO: dont forget to uncomment the rest of the if
    if new_username != "":  # and username not in clients_names:
        new_user_uuid = uuid.uuid4()
        new_user_uuid_str = str(new_user_uuid)
        clients_names.append(new_username)
        try:
            save_new_user_in_db(db_connection, (new_user_uuid_str, new_username, '', time.time(), ''))
            send_msg_to_client(user_conn,
                               struct.pack('<BHI16s', 3, MsgTypes.REGISTER_OK.value, 16, new_user_uuid.bytes))
            return new_user_uuid
        except Exception as e:
            print("ERROR: new user failed to save in the DB, ", e)
    else:
        print("WARNING: user name allready exsist or was not sent")
    return False


def send_encrypted_aes_key(user_conn, client_msg_payload, user_uuid_for_aes_key):
    ras_public_key = get_field_from_payload(client_msg_payload, 255, 415)
    try:
        save_user_public_key(db_connection, str(user_uuid_for_aes_key), ras_public_key)
    except Exception as save_ras_error:
        print("ERROR: RAS public key failed to save in the DB, ", save_ras_error)
        return False

    aes_key = get_random_bytes(16)
    save_user_aes_key(db_connection, str(user_uuid_for_aes_key), aes_key)
    cipher = PKCS1_OAEP.new(RSA.importKey(ras_public_key))
    encrypted_aes_key = cipher.encrypt(aes_key)
    send_msg_to_client(user_conn,
                       struct.pack('<BHI16s128s', 3, MsgTypes.SEND_AES_KEY.value,
                                   16 + len(encrypted_aes_key),
                                   user_uuid_for_aes_key.bytes,
                                   encrypted_aes_key))
    return aes_key


def send_file_crc(user_conn, client_msg_payload, user_uuid, aes_key):
    file_size = int.from_bytes(get_field_from_payload(client_msg_payload, 16, 20), byteorder='little', signed=False)
    file_name = get_field_from_payload(client_msg_payload, 20, 275, True)
    file_data = get_field_from_payload(client_msg_payload, 275, 275 + file_size)

    cipher_decrypt = AES.new(aes_key, AES.MODE_CBC, b"0000000000000000")
    decrypt_file_data = cipher_decrypt.decrypt(file_data)
    # TODO: fix bug for first 16 chars
    decrypt_file_data = decrypt_file_data[16:len(decrypt_file_data):1]
    decrypt_file_data_clean = decrypt_file_data.decode().replace('\r', '')
    decrypt_file_data_clean_bytes = decrypt_file_data_clean.encode('utf-8')
    file_data_crc = zlib.crc32(decrypt_file_data_clean_bytes)
    send_msg_to_client(user_conn, struct.pack('<BHI16sI255sI', 3, MsgTypes.SEND_CRC.value,
                                              16 + 4 + 255 + 4,
                                              user_uuid.bytes,
                                              file_size,
                                              file_name.encode('utf-8'),
                                              file_data_crc))
    return decrypt_file_data_clean


def update_crc(user_uuid, client_msg_payload):
    file_name = get_field_from_payload(client_msg_payload, 16, 16 + 255, True)
    return update_file_crc_verified(db_connection, user_uuid, file_name)


def save_file(user_conn, client_msg_payload, user_uuid_str, file_data):
    file_name = get_field_from_payload(client_msg_payload, 16 + 4, 255 + 16 + 4, True)
    try:
        if not os.path.exists("users files"):
            os.mkdir("users files")
        if not os.path.exists("users files\\" + user_uuid_str):
            os.mkdir("users files\\" + user_uuid_str)
        path_name = "users files\\" + user_uuid_str + '\\' + file_name
        file_to_save = open(path_name, 'w')
        file_to_save.write(file_data)
        file_to_save.close()
    except Exception as file_error:
        print("ERROR: faild to create diretory for save file, ", file_error)
        return False
    if not save_new_file_data(db_connection, user_uuid_str, file_name, path_name):
        return False

    send_msg_to_client(user_conn, struct.pack('<BHI', 3, MsgTypes.GOT_REQUEST.value, 0))
    return True


def user_communication(user_conn):
    user_uuid = None
    aes_key = None

    while True:
        try:
            client_msg_header, client_msg_payload = get_client_msg(user_conn)
            request_code = client_msg_header["Code"]

            if request_code == RequestType.REGISTER.value:
                print("\nTrying to register new user...")
                user_uuid = register_user(user_conn, client_msg_payload)
                if not user_uuid:
                    print("failed new user registration")
                    send_msg_to_client(
                        user_conn, "FAILD")
                    break
                print("Succeeded new user registration, user uuid: ", user_uuid)

            elif request_code == RequestType.SEND_KEY.value:
                print("\nTrying to send encrypte aes key for " + str(user_uuid) + "...")
                aes_key = send_encrypted_aes_key(user_conn, client_msg_payload, user_uuid)
                if not aes_key:
                    print("Failed to send encrypte aes key for ", user_uuid)
                    send_msg_to_client(user_conn, "FAILD")
                    break
                print("Succeeded to send encrypte aes key, aes key: " + str(aes_key) + " for " + str(user_uuid))

            elif request_code == RequestType.SEND_FILE.value:
                print("\nTrying to send file crc for " + str(user_uuid) + "...")
                decrypt_data = send_file_crc(user_conn, client_msg_payload, user_uuid, aes_key)
                if not decrypt_data:
                    print("Failed to send file crc for " + str(user_uuid))
                    send_msg_to_client(user_conn, "FAILD")
                    break
                print("Succeeded to send file crc, decrypt_data " + decrypt_data + " for " + str(user_uuid))
                print("\nTrying to save file for " + str(user_uuid) + "...")
                is_save_file_succeeded = save_file(user_conn, client_msg_payload, str(user_uuid), decrypt_data)
                if not is_save_file_succeeded:
                    print("Failed to save file for " + str(user_uuid))
                    send_msg_to_client(user_conn, "FAILD")
                    break
                else:
                    print("Succeeded to save file for " + str(user_uuid))

            elif request_code == RequestType.CRC_OK.value:
                print("\nTrying to update db the crc is verified for " + str(user_uuid) + "...")
                is_update_crc_succeeded = update_crc(str(user_uuid), client_msg_payload)

                if not is_update_crc_succeeded:
                    print("Failed to update db the crc is verified for " + str(user_uuid))
                else:
                    print("Succeeded to update db the crc is verified for " + str(user_uuid))
                    break

            elif request_code == RequestType.CRC_NOT_OK_RESEND.value:
                print("Warning: crc did not match on client side, trying again for " + str(user_uuid))
                send_msg_to_client(user_conn, struct.pack('<BHI', 3, MsgTypes.GOT_REQUEST.value, 0))

            elif request_code == RequestType.CRC_NOT_OK_ABORT.value:
                print("Error: crc did not match on client side for the fourth time for " + str(user_uuid))
                send_msg_to_client(user_conn, struct.pack('<BHI', 3, MsgTypes.GOT_REQUEST.value, 0))
                break

            else:
                print("WARNING: request type code is unknown or was not sent for " + str(user_uuid))
                if request_code:
                    print("request_code: ", request_code)
                break

        except Exception as error:
            print("General error\n", error)
            break


if __name__ == '__main__':
    db_connection = init_db(clients_names)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', get_port()))
    server_socket.listen()

    while True:
        conn, addr = server_socket.accept()
        print('Connected by', addr)
        x = threading.Thread(target=user_communication, args=(conn,))
        x.start()
