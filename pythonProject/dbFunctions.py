import sqlite3


def init_db(clients_names):
    db_connection = create_db_conection()
    if not db_connection:
        exit()
    else:
        if not init_db_tables(db_connection):
            exit()
        else:
            for client_name_data in get_clients_names(db_connection):
                clients_names.append(client_name_data[0])
    return db_connection


def create_db_conection():
    try:
        conn = sqlite3.connect("server", check_same_thread=False)
        return conn
    except Exception as db_error:
        print("ERROR: faild to create db connection: ", db_error)
        return False


def create_table(conn, create_table_sql):
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
        return True
    except Exception as db_error:
        print("ERROR: faild to create db table\n", db_error)
        return False


def init_db_tables(conn):
    # TODO: change fileds the the right size
    sql_create_clients_table = """ CREATE TABLE IF NOT EXISTS clients (
                                            ID text PRIMARY KEY,
                                            Name text NOT NULL,
                                            Public_key BLOB(160),
                                            Last_seen text NOT NULL,
                                            AES_key BLOB(16)
                                        ); """
    sql_create_files_table = """ CREATE TABLE IF NOT EXISTS files (
                                                ID text PRIMARY KEY,
                                                File_Name text NOT NULL,
                                                Path_Name text NOT NULL,
                                                Verified INTEGER NOT NULL
                                            ); """
    is_create_client_table_ok = create_table(conn, sql_create_clients_table)
    is_create_files_table_ok = create_table(conn, sql_create_files_table)
    return is_create_client_table_ok and is_create_files_table_ok


def get_clients_names(conn):
    cur = conn.cursor()
    cur.execute("SELECT Name FROM clients")
    return cur.fetchall()


def save_new_user_in_db(conn, client_info):
    sql = ''' INSERT INTO clients(id, Name, Public_key, Last_seen, AES_key)
                      VALUES(?, ?, ?, ?, ?); '''
    cur = conn.cursor()
    cur.execute(sql, client_info)
    conn.commit()

    return cur.lastrowid


def save_user_public_key(conn, client_id, public_key):
    sql = ''' UPDATE clients
                  SET Public_key = ?
                  WHERE ID = ?;'''
    cur = conn.cursor()
    cur.execute(sql, (public_key, client_id))
    conn.commit()

    return cur.lastrowid


# TODO: use this function after creating the aes key
def save_user_aes_key(conn, client_id, aes_key):
    sql = ''' UPDATE clients
                  SET AES_key = ?
                  WHERE ID = ?;'''
    cur = conn.cursor()
    cur.execute(sql, (aes_key, client_id))
    conn.commit()

    return cur.lastrowid


def save_new_file_data(conn, client_id, filename, path_name):
    sql = ''' INSERT INTO files (id, File_Name, Path_Name, Verified)
                      VALUES(?, ?, ?, ?);'''
    cur = conn.cursor()
    cur.execute(sql, (client_id, filename, path_name, 0))
    conn.commit()
    return cur.lastrowid


def update_file_crc_verified(conn, client_id, filename):
    sql = ''' UPDATE files SET Verified = 1 WHERE id = ? and File_Name = ?;'''
    cur = conn.cursor()
    cur.execute(sql, (client_id, filename))
    conn.commit()
    return cur.lastrowid
