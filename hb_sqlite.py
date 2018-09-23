import sqlite3
from time import time
from json import loads, dumps
from struct import pack, unpack
from socket import inet_aton, inet_ntoa

DB_FILE = "clients.db"

class Database(object):
    conn = None

    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE)
        c = self.conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS clients(address integer, timestamp integer, dmr_ids text)")
        self.conn.commit()

    def add_client(self, address):
        row = self.client_exists(address)
        if row is None:
            address = self.ip2long(address)
            timestamp = self.unix_timestamp()
            c = self.conn.cursor()
            c.execute("INSERT INTO clients VALUES (?, ?, ?)", (address, timestamp, dumps([])))
            self.conn.commit()
            return True
        return False

    def remove_client(self, address):
        row = self.client_exists(address)
        if row is not None:
            address = self.ip2long(address)
            c = self.conn.cursor()
            c.execute("DELETE FROM clients WHERE address=?", (address,))
            self.conn.commit()
            return True
        return False

    def update_timestamp(self, address):
        row = self.client_exists(address)
        if row is not None:
            address = self.ip2long(address)
            c = self.conn.cursor()
            c.execute("UPDATE clients SET timestamp=? WHERE address=?", (self.unix_timestamp(), address))
            self.conn.commit()
            return True
        return False

    def get_num_dmrs(self, address):
        row = self.client_exists(address)
        if row is not None:
            return len(loads(row[2]))
        return False

    def add_dmr_to_client(self, address, dmr_id):
        row = self.client_exists(address)
        if row is not None:
            address = self.ip2long(address)
            dmr_ids = loads(row[2])
            if dmr_id not in dmr_ids:
                dmr_ids.append(dmr_id)
                c = self.conn.cursor()
                c.execute("UPDATE clients SET timestamp=?,dmr_ids=? WHERE address=?", (self.unix_timestamp(), dumps(dmr_ids), address))
                self.conn.commit()
                return True
        return False

    def remove_dmr_from_client(self, address, dmr_id):
        row = self.client_exists(address)
        if row is not None:
            address = self.ip2long(address)
            dmr_ids = loads(row[2])
            if dmr_id in dmr_ids:
                dmr_ids.remove(dmr_id)
                c = self.conn.cursor()
                c.execute("UPDATE clients SET timestamp=?,dmr_ids=? WHERE address=?", (self.unix_timestamp(), dumps(dmr_ids), address))
                self.conn.commit()
                return True
        return False

    def client_exists(self, address):
        address = self.ip2long(address)
        c = self.conn.cursor()
        c.execute("SELECT * FROM clients WHERE address=?", (address,))
        return c.fetchone()

    def dmr_exists(self, address, dmr_id):
        row = self.client_exists(address)
        if row is not None:
            return dmr_id in loads(row[2])
        return False

    def unix_timestamp(self):
        return int(time())

    def ip2long(self, address):
        return unpack("!L", inet_aton(address))[0]

    def long2ip(self, value):
        return inet_ntoa(pack('!L', value))
