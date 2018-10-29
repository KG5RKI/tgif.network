from sqlalchemy import Boolean, Column, DateTime, Integer, LargeBinary, String, create_engine, BigInteger, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from struct import pack, unpack
from socket import inet_aton, inet_ntoa

Base = declarative_base()


def open_database():
    return create_engine('mysql://tgif:bi9tKWXyT4i6wVBv@localhost/tgif')

def ip2long(address):
    return unpack("!L", inet_aton(address))[0]

def long2ip(addr):
    return inet_ntoa(pack('!L', addr))

def create_session_factory(engine):
    return sessionmaker(bind=engine)


class repeater(Base):
    __tablename__ = 'repeater'

    id = Column(Integer, primary_key=True)

    # identifying bits
    address = Column(BigInteger)
    port = Column(Integer)
    repeater_id = Column(Integer)
    dmr_ids = Column(String(1000))
    last_ping = Column(Integer)
    salt = Column(BigInteger)
    connection = Column(String(32))
    tg = Column(Integer)

    def __init__(self, addr, id):
        self.address = addr
        self.repeater_id = id
        self.dmr_ids = "[]"
        self.last_ping = 0
        self.salt = 0
        self.port = 0
        self.connection = "NO"
        self.tg = 9

    def __repr__(self):
        return "<('{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}')>".format(long2ip(self.address), self.repeater_id, self.dmr_ids, self.last_ping, self.salt, self.port, self.connection, self.tg)

class client_info(Base):
    __tablename__ = 'client_info'

    id = Column(Integer, primary_key=True)

    # identifying bits
    ip_address = Column(String(22))
    radio_id = Column(Integer)
    callsign = Column(String(12))
    rx_freq = Column(String(15))
    tx_freq = Column(String(15))
    tx_power = Column(String(12))
    colorcode = Column(Integer)
    latitude = Column(Float)
    longitude = Column(Float)
    height = Column(Float)
    location = Column(String(20))
    description = Column(String(35))
    slots = Column(Integer)
    url = Column(String(400))
    software_id = Column(String(66))
    package_id = Column(String(164))
    last_connect = Column(Integer)

    def __init__(self, addr, id):
        self.ip_address = addr
        self.radio_id = id
        self.last_connect = 0
        self.slots = 0
        self.height = 0
        self.longitude = 0
        self.latitude = 0
        self.colorcode = 0

        self.callsign = 'UNK'
        self.rx_freq = 'UNK'
        self.tx_freq = 'UNK'
        self.tx_power = 'UNK'
        self.location = 'UNK'
        self.description = 'UNK'
        self.url = 'UNK'
        self.software_id = 'UNK'
        self.package_id = 'UNK'

    def __repr__(self):
        return "<('{0}', '{1}', '{2}')>".format(self.address, self.repeater_id, self.dmr_ids)


class talkgroup(Base):
    __tablename__ = 'talkgroups'

    id = Column(Integer, primary_key=True)

    # identifying bits
    talkgroup = Column(Integer)
    last_station = Column(Integer)
    timestamp = Column(Integer)
    stream_id = Column(BigInteger)
    

    def __init__(self, talkgroup):
        self.talkgroup = talkgroup
        self.last_station = 0
        self.timestamp = 0
        self.stream_id = 0

    def __repr__(self):
        return "<('{0}', '{1}', '{2}')>".format(self.address, self.repeater_id, self.dmr_ids)


class lastheard(Base):
    __tablename__ = 'lastheard'

    id = Column(Integer, primary_key=True)

    # identifying bits
    ip_address = Column(String(22))
    radio_id = Column(Integer)
    callsign = Column(String(12))
    talkgroup = Column(Integer)
    timestamp = Column(Integer)
    

    def __init__(self, talkgroup, callsign, radio_id, ip, timestamp):
        self.talkgroup = talkgroup
        self.callsign = callsign
        self.timestamp = timestamp
        self.ip_address = ip
        self.radio_id = radio_id

    def __repr__(self):
        return "<('{0}', '{1}', '{2}')>".format(self.address, self.repeater_id, self.dmr_ids)
