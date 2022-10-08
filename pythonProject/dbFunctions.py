import sqlite3


def create_db_conection():
    try:
        conn = sqlite3.connect("server")
        return conn
    except Exception:
        print("ERROR: faild to create db connection: ", Exception)
        return False


def create_table(conn, create_table_sql):
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
        return True
    except Exception:
        print("ERROR: faild to create db table\n", Exception)
        return False


def init_db_tables(conn):
    sql_create_clients_table = """ CREATE TABLE IF NOT EXISTS clients (
                                            ID text PRIMARY KEY,
                                            Name text NOT NULL,
                                            Public_key text,
                                            Last_seen text,
                                            AES_key text
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
                      VALUES(?, ?, ?, ?, ?) '''
    cur = conn.cursor()
    cur.execute(sql, client_info)
    conn.commit()

    return cur.lastrowid


def save_user_public_key(conn, client_id, public_key):
    sql = ''' UPDATE clients
                  SET Public_key = ?
                  WHERE id = ?'''
    cur = conn.cursor()
    cur.execute(sql, (public_key, str(client_id)))
    conn.commit()

    return cur.lastrowid
