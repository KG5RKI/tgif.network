#!/usr/bin/env python
#
###############################################################################
#   Copyright (C) 2016  Cortney T. Buffington, N0MJS <n0mjs@me.com>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software Foundation,
#   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
###############################################################################

'''
This program does very little on it's own. It is intended to be used as a module
to build applcaitons on top of the HomeBrew Repeater Protocol. By itself, it
will only act as a client or master for the systems specified in its configuration
file (usually hblink.cfg). It is ALWAYS best practice to ensure that this program
works stand-alone before troubleshooting any applicaitons that use it. It has
sufficient logging to be used standalone as a troubeshooting application.
'''

from __future__ import print_function

# Specifig functions from modules we need
from binascii import b2a_hex as ahex
from binascii import a2b_hex as bhex
from random import randint
from hashlib import sha256
from time import time
from bitstring import BitArray
import socket
import sys
import json
from importlib import import_module
import socket

# Twisted is pretty important, so I keep it separate
from twisted.internet.protocol import DatagramProtocol, Factory, Protocol
from twisted.internet import reactor
from twisted.protocols.basic import NetstringReceiver
from twisted.internet import task

# Other files we pull from -- this is mostly for readability and segmentation
import hb_log
import hb_config
from hb_sqlite import *
from dmr_utils.utils import int_id, hex_str_4
import database as db

import cPickle as pickle
from reporting_const import *

# Does anybody read this stuff? There's a PEP somewhere that says I should do this.
__author__     = 'Cortney T. Buffington, N0MJS'
__copyright__  = 'Copyright (c) 2016 Cortney T. Buffington, N0MJS and the K0USY Group'
__credits__    = 'Colin Durbridge, G4EML, Steve Zingman, N4IRS; Mike Zingman, N4IRR; Jonathan Naylor, G4KLX; Hans Barthen, DL5DI; Torsten Shultze, DG1HT'
__license__    = 'GNU GPLv3'
__maintainer__ = 'Cort Buffington, N0MJS'
__email__      = 'n0mjs@me.com'


# Global variables used whether we are a module or __main__
systems = {}

# SQLite database
dbb = Database()

dmrd_last_ip = {}
dmrd_last_time = {}
dmrd_last_vseq = {}

def config_reports(_config, _logger, _factory):                 
    if True: #_config['REPORTS']['REPORT']:
        def reporting_loop(_logger, _server):
            _logger.debug('Periodic reporting loop started')
            _server.send_config()
            
        _logger.info('HBlink TCP reporting server configured')
        
        report_server = _factory(_config, _logger)
        report_server.clients = []
        reactor.listenTCP(_config['REPORTS']['REPORT_PORT'], report_server)
        
        reporting = task.LoopingCall(reporting_loop, _logger, report_server)
        reporting.start(_config['REPORTS']['REPORT_INTERVAL'])
    
    return report_server

# Shut ourselves down gracefully by disconnecting from the masters and clients.
def hblink_handler(_signal, _frame, _logger):
    for system in systems:
        _logger.info('SHUTDOWN: DE-REGISTER SYSTEM: %s', system)
        systems[system].dereg()


#************************************************
#     AMBE CLASS: Used to parse out AMBE and send to gateway
#************************************************

class AMBE:
    def __init__(self, _config, _logger):
        self._CONFIG = _config
         
        self._sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self._exp_ip = self._CONFIG['AMBE']['EXPORT_IP']
        self._exp_port = self._CONFIG['AMBE']['EXPORT_PORT']

    def parseAMBE(self, _client, _data):
        _seq = int_id(_data[4:5])
        _srcID = int_id(_data[5:8])
        _dstID = int_id(_data[8:11])
        _rptID = int_id(_data[11:15])
        _bits = int_id(_data[15:16])       # SCDV NNNN (Slot|Call type|Data|Voice|Seq or Data type)
        _slot = 2 if _bits & 0x80 else 1
        _callType = 1 if (_bits & 0x40) else 0
        _frameType = (_bits & 0x30) >> 4
        _voiceSeq = (_bits & 0x0f)
        _streamID = int_id(_data[16:20])
        logger.debug('(%s) seq: %d srcID: %d dstID: %d rptID: %d bits: %0X slot:%d callType: %d frameType:  %d voiceSeq: %d streamID: %0X',
        _client, _seq, _srcID, _dstID, _rptID, _bits, _slot, _callType, _frameType, _voiceSeq, _streamID )

        #logger.debug('Frame 1:(%s)', self.ByteToHex(_data))
        _dmr_frame = BitArray('0x'+ahex(_data[20:]))
        _ambe = _dmr_frame[0:108] + _dmr_frame[156:264]
        #_sock.sendto(_ambe.tobytes(), ("127.0.0.1", 31000))

        ambeBytes = _ambe.tobytes()
        self._sock.sendto(ambeBytes[0:9], (self._exp_ip, self._exp_port))
        self._sock.sendto(ambeBytes[9:18], (self._exp_ip, self._exp_port))
        self._sock.sendto(ambeBytes[18:27], (self._exp_ip, self._exp_port))


#************************************************
#     HB MASTER CLASS
#************************************************

def try_find_client(sqldb, address, repeater_id, **kwargs):
    client = sqldb.query(db.repeater).filter_by(address=address, repeater_id=repeater_id).first()

    # user not found
    if not client:
        client = db.repeater(address, repeater_id)
        client.address = address
        client.repeater_id = repeater_id
        sqldb.add(client)
        sqldb.commit()
        #self._logger.info('%s: added repeater %s', address, repeater_id)
        return client
        #else:
            #self._logger.info('%s: found repeater %s', address, repeater_id)

    return client

def get_routes(sqldb, tgnum):
    clients = sqldb.query(db.repeater).filter(db.repeater.tg==tgnum, time() - db.repeater.last_ping < 100, db.repeater.connection == "YES")

    return clients

def get_talkgroup(sqldb, tgnum):
    talkgroup = sqldb.query(db.talkgroup).filter(db.talkgroup.talkgroup==tgnum).first()
    if not talkgroup:
        talkgroup = db.talkgroup(tgnum)
        sqldb.add(talkgroup)
        sqldb.commit()
        #self._logger.info('Added new talkgroup: %s', tgnum)
    return talkgroup
    
def get_client_info(sqldb, address, repeater_id, **kwargs):
    client = sqldb.query(db.client_info).filter_by(radio_id=repeater_id, ip_address=address).first()

    # user not found
    if not client:
        client = db.client_info(address, repeater_id)
        client.address = address
        client.repeater_id = repeater_id
        sqldb.add(client)
        sqldb.commit()
        #self._logger.info('%s: added client_info %s', address, repeater_id)
        return client
        #else:
            #self._logger.info('%s: found repeater %s', address, repeater_id)

    return client

class HBSYSTEM(DatagramProtocol):
    
    def __init__(self, _name, _config, _logger, _report):
        # Define a few shortcuts to make the rest of the class more readable
        self._CONFIG = _config
        self._system = _name
        self._logger = _logger
        self._report = _report
        self._config = self._CONFIG['SYSTEMS'][self._system]
        sys.excepthook = self.handle_exception

        self.engine = db.open_database()
        self.Session = db.create_session_factory(self.engine)
        #self.db = self.Session()
        self._logger.info('Opening SQL Session')

        
        # Define shortcuts and generic function names based on the type of system we are
        if self._config['MODE'] == 'MASTER':
            self._clients = self._CONFIG['SYSTEMS'][self._system]['CLIENTS']
            self.send_system = self.send_clients
            self.maintenance_loop = self.master_maintenance_loop
            self.datagramReceived = self.master_datagramReceived
            self.dereg = self.master_dereg
        
        elif self._config['MODE'] == 'CLIENT':
            self._stats = self._config['STATS']
            self.send_system = self.send_master
            self.maintenance_loop = self.client_maintenance_loop
            self.datagramReceived = self.client_datagramReceived
            self.dereg = self.client_dereg
        
        # Configure for AMBE audio export if enabled
        if self._config['EXPORT_AMBE']:
            self._ambe = AMBE(_config, _logger)

    

    def handle_exception(self, exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        self._logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

    def startProtocol(self):
        # Set up periodic loop for tracking pings from clients. Run every 'PING_TIME' seconds
        self._system_maintenance = task.LoopingCall(self.maintenance_loop)
        self._system_maintenance_loop = self._system_maintenance.start(self._CONFIG['GLOBAL']['PING_TIME'])
    
    # Aliased in __init__ to maintenance_loop if system is a master
    def master_maintenance_loop(self):
        self._logger.debug('(%s) Master maintenance loop started', self._system)
        for client in self._clients:
            _this_client = self._clients[client]
            # Check to see if any of the clients have been quiet (no ping) longer than allowed
            if _this_client['LAST_PING']+self._CONFIG['GLOBAL']['PING_TIME']*self._CONFIG['GLOBAL']['MAX_MISSED'] < time():
                self._logger.info('(%s) Client %s (%s) has timed out', self._system, _this_client['CALLSIGN'], _this_client['RADIO_ID'])
                # Remove any timed out clients from the configuration
                del self._CONFIG['SYSTEMS'][self._system]['CLIENTS'][client]
    
    # Aliased in __init__ to maintenance_loop if system is a client           
    def client_maintenance_loop(self):
        self._logger.debug('(%s) Client maintenance loop started', self._system)
        if self._stats['PING_OUTSTANDING']:
            self._stats['NUM_OUTSTANDING'] += 1
        # If we're not connected, zero out the stats and send a login request RPTL
        if self._stats['CONNECTION'] == 'NO' or self._stats['CONNECTION'] == 'RPTL_SENT' or self._stats['NUM_OUTSTANDING'] >= self._CONFIG['GLOBAL']['MAX_MISSED']:
            self._stats['PINGS_SENT'] = 0
            self._stats['PINGS_ACKD'] = 0
            self._stats['NUM_OUTSTANDING'] = 0
            self._stats['PING_OUTSTANDING'] = False
            self._stats['CONNECTION'] = 'RPTL_SENT'
            self.send_master('RPTL'+self._config['RADIO_ID'])
            self._logger.info('(%s) Sending login request to master %s:%s', self._system, self._config['MASTER_IP'], self._config['MASTER_PORT'])
        # If we are connected, sent a ping to the master and increment the counter
        if self._stats['CONNECTION'] == 'YES':
            self.send_master('RPTPING'+self._config['RADIO_ID'])
            self._logger.debug('(%s) RPTPING Sent to Master. Total Sent: %s, Total Missed: %s, Currently Outstanding: %s', self._system, self._stats['PINGS_SENT'], self._stats['PINGS_SENT'] - self._stats['PINGS_ACKD'], self._stats['NUM_OUTSTANDING'])
            self._stats['PINGS_SENT'] += 1
            self._stats['PING_OUTSTANDING'] = True

    def send_clients(self, _packet):
        for _client in self._clients:
            self.send_client(_client, _packet)
            #self._logger.debug('(%s) Packet sent to client %s', self._system, self._clients[_client]['RADIO_ID'])

    def send_client(self, _client, _packet):
        _ip = self._clients[_client]['IP']
        _port = self._clients[_client]['PORT']
        self.transport.write(_packet, (_ip, _port))
        # KEEP THE FOLLOWING COMMENTED OUT UNLESS YOU'RE DEBUGGING DEEPLY!!!!
        #self._logger.debug('(%s) TX Packet to %s on port %s: %s', self._clients[_client]['RADIO_ID'], self._clients[_client]['IP'], self._clients[_client]['PORT'], ahex(_packet))

    def send_master(self, _packet):
        self.transport.write(_packet, (self._config['MASTER_IP'], self._config['MASTER_PORT']))
        # KEEP THE FOLLOWING COMMENTED OUT UNLESS YOU'RE DEBUGGING DEEPLY!!!!
        #self._logger.debug('(%s) TX Packet to %s:%s -- %s', self._system, self._config['MASTER_IP'], self._config['MASTER_PORT'], ahex(_packet))

    def dmrd_received(self, _radio_id, _rf_src, _dst_id, _seq, _slot, _call_type, _frame_type, _dtype_vseq, _stream_id, _data):
        pass
    
    def master_dereg(self):
        print("nope")
        
        #for _client in self._clients:
        #    self.send_client(_client, 'MSTCL'+_client)
        #    self._logger.info('(%s) De-Registration sent to Client: %s (%s)', self._system, self._clients[_client]['CALLSIGN'], self._clients[_client]['RADIO_ID'])
            
    def client_dereg(self):
        self.send_master('RPTCL'+self._config['RADIO_ID'])
        self._logger.info('(%s) De-Registeration sent to Master: %s:%s', self._system, self._config['MASTER_IP'], self._config['MASTER_PORT'])
    
    def check_dmrid(self, dmrid):
        if dmrid<10000: #or dmrid==310033:
            return False
        return True

    # Aliased in __init__ to datagramReceived if system is a master
    def master_datagramReceived(self, _data, (_host, _port)):
        global dmrd_last_ip
        global dmrd_last_time

        # Keep This Line Commented Unless HEAVILY Debugging!
        #self._logger.debug('(%s) RX packet from %s:%s -- %s', self._system, _host, _port, ahex(_data))

        # Extract the command, which is various length, all but one 4 significant characters -- RPTCL
        _command = _data[:4]
        sqldb = self.Session()
        if _command == 'DMRD':    # DMRData -- encapsulated DMR data frame
            _radio_id = _data[11:15]
            
            client = try_find_client(sqldb, db.ip2long(_host), int(ahex(_radio_id), 16))
            if _radio_id in self._clients \
                        and self._clients[_radio_id]['CONNECTION'] == 'YES' \
                        and self._clients[_radio_id]['IP'] == _host \
                        and self._clients[_radio_id]['PORT'] == _port:
                _seq = _data[4]
                _rf_src = _data[5:8]
                _dst_id = _data[8:11]
                _bits = int_id(_data[15])
                _slot = 2 if (_bits & 0x80) else 1
                _call_type = 'unit' if (_bits & 0x40) else 'group'
                _frame_type = (_bits & 0x30) >> 4
                _dtype_vseq = (_bits & 0xF) # data, 1=voice header, 2=voice terminator; voice, 0=burst A ... 5=burst F
                _stream_id = _data[16:20]
                _dst_id_int = int_id(_dst_id)
                if _dst_id_int == 0:
                    return
                if self._clients[_radio_id]['TG'] != _dst_id_int:

                    self._clients[_radio_id]['TG'] = _dst_id_int
                    client.tg = self._clients[_radio_id]['TG']
                    sqldb.commit() 
                #self._logger.debug('(%s) DMRD - Seqence: %s, RF Source: %s, Destination ID: %s', self._system, int_id(_seq), int_id(_rf_src), int_id(_dst_id))

                # If AMBE audio exporting is configured...
                if self._config['EXPORT_AMBE']:
                    self._ambe.parseAMBE(self._system, _data)
                
                _dmr_frame = BitArray('0x'+ahex(_data[20:]))
                _ambe = _dmr_frame[0:108] + _dmr_frame[156:264]
                #_sock.sendto(_ambe.tobytes(), ("127.0.0.1", 31000))

                #ambeBytes = _ambe.tobytes()
                #self._sock.sendto(ambeBytes[0:9], ("127.0.0.1", 3333))
                #self._sock.sendto(ambeBytes[9:18], ("127.0.0.1", 3333))
                #self._sock.sendto(ambeBytes[18:27], ("127.0.0.1", 3333))
                

                # database logic
                client_ip = _host
                dmr_id = unpack("!I", "\x00" + _rf_src)[0]
                if dbb.add_client(client_ip):
                    self._logger.info("(%s) Added client IP %s to the database", self._system, client_ip)
                dbb.update_timestamp(client_ip)
                if dbb.add_dmr_to_client(client_ip, dmr_id):
                    self._logger.info("(%s) Added a new DMR ID (%s) to %s", self._system, dmr_id, client_ip)
                #else:  # client failed to add a new DMR ID
                    #flag_count = 3
                    #num_dmrs = db.get_num_dmrs(client_ip)
                    #if num_dmrs > flag_count:
                        #self._logger.info("(%s) %s is trying to add more than %s DMR ID(s) (%s)", self._system, client_ip, flag_count, dmr_id)

                # The basic purpose of a master is to repeat to the clients
                if self._config['REPEAT'] == True and _call_type == 'group':


	
                    cur_time = time()
                    client_ip = self._clients[_radio_id]['IP']
                    okgo = 0
                    ind = str(int_id(_dst_id))
                    
                    #if ind not in dmrd_last_vseq:
                    #    dmrd_last_vseq[ind] = hb_const.HBPF_SLT_VHEAD
                        
                    try:
                        if ind not in dmrd_last_ip:
                            dmrd_last_ip[ind] = client_ip

                        if dmrd_last_ip[ind] != client_ip:
                            if ind not in dmrd_last_time:
                                dmrd_last_time[ind] = cur_time
                                okgo = 1
                                self._logger.debug('dmrd new tg dest %s', ind)
                            elif (cur_time - dmrd_last_time[ind]) > 2:
                                dmrd_last_ip[ind] = client_ip
                                okgo = 1
                                self._logger.debug('dmrd_ > 2 %d', cur_time)
                            else:
                            	self._logger.debug('dmrd_last_ip %s', dmrd_last_ip[ind])
                        else:
                            okgo = 1
                        dmrd_last_time[ind] = cur_time
                    except:
                        okgo = 1
                        self._logger.warning('Failed to get tg info for %d', int_id(_dst_id_int))

                    #if (_frame_type == hb_const.HBPF_DATA_SYNC) and (_dtype_vseq == hb_const.HBPF_SLT_VHEAD): #and (dmrd_last_vseq[ind] == hb_const.HBPF_SLT_VTERM):
                    #    self._logger.info('Call START from %s on TG %s - %s', self._clients[_radio_id]['CALLSIGN'], int_id(_dst_id), int_id(_stream_id) )
                    #if (_dtype_vseq == hb_const.HBPF_SLT_VTERM):
                    #    self._logger.info('Call END from %s on TG %s - %s', self._clients[_radio_id]['CALLSIGN'], int_id(_dst_id), int_id(_stream_id) )
										

                    
                    if okgo == 1 and _rf_src != 0 and _radio_id != 0:
                    	   #self._logger.debug('(%s) Packet on TS%s from %s (%s) for destination ID %s [Stream ID: %s]', self._system, _slot, self._clients[_radio_id]['CALLSIGN'], int_id(_radio_id), int_id(_dst_id), int_id(_stream_id))
                        talkgroup = get_talkgroup(sqldb, _dst_id_int)
                        if(talkgroup.stream_id != int_id(_stream_id)):
                            talkgroup.stream_id = int_id(_stream_id)
                            talkgroup.last_station = int_id(_radio_id)
                            talkgroup.timestamp = time()

                            info = get_client_info(sqldb, _host, int(ahex(_radio_id), 16))
                            lastheard = db.lastheard(_dst_id_int, info.callsign, dmr_id, db.ip2long(_host), time())
                            sqldb.add(lastheard)
                            sqldb.commit()
                            self._logger.info('(%s) Packet on TS%s from %s (%s) for destination ID %s [Stream: %s]', self._system, _slot, self._clients[_radio_id]['CALLSIGN'], int_id(_radio_id), int_id(_dst_id), int_id(_stream_id))



                        #METHOD USING MYSQL, CAUSES MEMORY LEAK FIX LATER
                        clients = get_routes(sqldb, _dst_id_int)
                        
                        #self._logger.info('(%s) Packet on TS%s from %s (%s) for destination ID %s [Stream: %s]', self._system, _slot, self._clients[_radio_id]['CALLSIGN'], int_id(_radio_id), int_id(_dst_id), int_id(_stream_id))
                        for _client in clients:
                            if _client.repeater_id != int_id(_radio_id):
                                self._logger.info('(%s:%s) %s %s (%s) ', db.long2ip(_client.address), _client.port, _client.repeater_id, _client.tg, _client.connection)
                                _data = _data[0:11] + pack('>I', _client.repeater_id) + _data[15:]
                                self.transport.write(_data, (db.long2ip(_client.address), _client.port))
                                

                        #self._logger.info('(%s) Packet on TS%s from %s (%s) for destination ID %s [Stream: %s]', self._system, _slot, self._clients[_radio_id]['CALLSIGN'], int_id(_radio_id), int_id(_dst_id), int_id(_stream_id))
                        #for _client in self._clients:
                            #if _client != _radio_id and self._clients[_client]['CONNECTION'] == 'YES':
                                #if (self._clients[_client]['TG'] == _dst_id_int or self._clients[_client]['TG'] == 444411):

                                    #_data = _data[0:11] + _client + _data[15:]

                                    #self.send_client(_client, _data)
                                    #self._logger.info('(%s) Packet on TS%s from %s (%s) for destination ID %s repeated to client: %s (%s) [Stream ID: %s]', self._system, _slot, self._clients[_radio_id]['CALLSIGN'], int_id(_radio_id), int_id(_dst_id), self._clients[_client]['CALLSIGN'], int_id(_client), int_id(_stream_id))
                                #elif _dst_id_int == 9 and int(self._clients[_client]['TG']) == 31665:
                                #    self._logger.info('sending to TG31665')
                                    #._logger.info('(%s) Packet on TS%s from %s (%s) for destination ID %s swapped to %s repeated to client: %s (%s) [Stream ID: %s]', self._system, _slot, self._clients[_radio_id]['CALLSIGN'], int_id(_radio_id), int_id(_dst_id), self._clients[_client]['TG']), self._clients[_client]['CALLSIGN'], int_id(_client), int_id(_stream_id))
                                    
                                #    _data = _data[0:8] + hex_str_3(31665) + _client + _data[15:]
                                #    self.send_client(_client, _data)              
                               # elif _dst_id_int == 31665 and int(self._clients[_client]['TG']) == 9:
                                #    self._logger.info('sending to TG9')
                            #self._logger.info('(%s) Packet on TS%s from %s (%s) for destination ID %s swapped to %s  repeated to client: %s (%s) [Stream ID: %s]', self._system, _slot, self._clients[_radio_id]['CALLSIGN'], int_id(_radio_id), int_id(_dst_id), str(hex_str_4(self._clients[_client]['TG'])), self._clients[_client]['CALLSIGN'], int_id(_client), int_id(_stream_id))
                                #    _data = _data[0:8] + hex_str_3(9) + _client + _data[15:]
                               #     self.send_client(_client, _data)                                                           
                                #elif int_id(_dst_id) == 31665 && self._clients[_client]['TG'] == 31665:
                                    
                                #    _data = _data[0:11] + _client + _data[15:]

                                #    self.send_client(_client, _data) 
                        
                # Userland actions -- typically this is the function you subclass for an application
                self.dmrd_received(_radio_id, _rf_src, _dst_id, _seq, _slot, _call_type, _frame_type, _dtype_vseq, _stream_id, _data)

        elif _command == 'RPTL':    # RPTLogin -- a repeater wants to login
            _radio_id = _data[4:8]
            client = try_find_client(sqldb, db.ip2long(_host), int(ahex(_radio_id), 16))
            if _radio_id and self.check_dmrid(int(ahex(_radio_id), 16)):           # Future check here for valid Radio ID
                self._clients.update({_radio_id: {      # Build the configuration data strcuture for the client
                    'CONNECTION': 'RPTL-RECEIVED',
                    'PINGS_RECEIVED': 0,
                    'LAST_PING': time(),
                    'IP': _host,
                    'PORT': _port,
                    'SALT': randint(0,0xFFFFFFFF),
                    'RADIO_ID': str(int(ahex(_radio_id), 16)),
                    'CALLSIGN': '',
                    'RX_FREQ': '',
                    'TX_FREQ': '',
                    'TX_POWER': '',
                    'COLORCODE': '',
                    'LATITUDE': '',
                    'LONGITUDE': '',
                    'HEIGHT': '',
                    'LOCATION': '',
                    'DESCRIPTION': '',
                    'SLOTS': '',
                    'URL': '',
                    'SOFTWARE_ID': '',
                    'PACKAGE_ID': '',
                    'TG': client.tg,
                }})
                client.salt = self._clients[_radio_id]['SALT']
                client.last_ping = self._clients[_radio_id]['LAST_PING']
                client.port = _port

                self._logger.info('(%s) Repeater Logging in with Radio ID: %s, %s:%s', self._system, int_id(_radio_id), _host, _port)
                _salt_str = hex_str_4(self._clients[_radio_id]['SALT'])
                self.send_client(_radio_id, 'RPTACK'+_salt_str)
                self._clients[_radio_id]['CONNECTION'] = 'CHALLENGE_SENT'
                client.connection = self._clients[_radio_id]['CONNECTION']
                sqldb.commit()
                self._logger.info('(%s) Sent Challenge Response to %s for login: %s', self._system, int_id(_radio_id), self._clients[_radio_id]['SALT'])
            else:
                self.transport.write('MSTNAK'+_radio_id, (_host, _port))
                self._logger.warning('(%s) Invalid Login from Radio ID: %s', self._system, int_id(_radio_id))

        elif _command == 'RPTK':    # Repeater has answered our login challenge
            _radio_id = _data[4:8]
            client = try_find_client(sqldb, db.ip2long(_host), int(ahex(_radio_id), 16))
            if _radio_id in self._clients \
                        and self._clients[_radio_id]['CONNECTION'] == 'CHALLENGE_SENT' \
                        and self._clients[_radio_id]['IP'] == _host \
                        and self._clients[_radio_id]['PORT'] == _port:
                _this_client = self._clients[_radio_id]
                _this_client['LAST_PING'] = time()
                client.last_ping = _this_client['LAST_PING'] 
                _this_client['SALT'] = client.salt
                _sent_hash = _data[8:]
                _salt_str = hex_str_4(_this_client['SALT'])
                _calc_hash = bhex(sha256(_salt_str+self._config['PASSPHRASE']).hexdigest())
                if _sent_hash == _calc_hash:
                    _this_client['CONNECTION'] = 'WAITING_CONFIG'
                    client.connection = _this_client['CONNECTION']
                    sqldb.commit()
                    self.send_client(_radio_id, 'RPTACK'+_radio_id)
                    self._logger.info('(%s) Client %s has completed the login exchange successfully', self._system, _this_client['RADIO_ID'])
                else:
                    self._logger.info('test')
                    self._logger.info('(%s) Client %s has FAILED the login exchange successfully', self._system, _this_client['RADIO_ID'])
                    self._logger.info(' calc: %s - %s', _calc_hash.encode('hex'), _sent_hash.encode('hex'))
                    self.transport.write('MSTNAK'+_radio_id, (_host, _port))
                    client.connection = "NO"
                    sqldb.commit()
                    del self._clients[_radio_id]
            else:
                self.transport.write('MSTNAK'+_radio_id, (_host, _port))
                self._logger.warning('(%s) Login challenge from Radio ID that has not logged in: %s', self._system, int_id(_radio_id))

        elif _command == 'RPTC':    # Repeater is sending it's configuraiton OR disconnecting
            if _data[:5] == 'RPTCL':    # Disconnect command
                _radio_id = _data[5:9]
                client = try_find_client(sqldb, db.ip2long(_host), int(ahex(_radio_id), 16))
                if _radio_id in self._clients \
                            and self._clients[_radio_id]['CONNECTION'] == 'YES' \
                            and self._clients[_radio_id]['IP'] == _host \
                            and self._clients[_radio_id]['PORT'] == _port:
                    client.connection = "NO"
                    sqldb.commit()
                    self._logger.info('(%s) Client is closing down: %s (%s)', self._system, self._clients[_radio_id]['CALLSIGN'], int_id(_radio_id))
                    self.transport.write('MSTNAK'+_radio_id, (_host, _port))
                    del self._clients[_radio_id]
            
            else:
                _radio_id = _data[4:8]      # Configure Command
                client = try_find_client(sqldb, db.ip2long(_host), int(ahex(_radio_id), 16))
                if _radio_id not in self._clients and client and self.check_dmrid(int(ahex(_radio_id), 16)):
                    self._clients.update({_radio_id: {      # Build the configuration data strcuture for the client
                        'CONNECTION': 'YES',
                        'PINGS_RECEIVED': 0,
                        'LAST_PING': time(),
                        'IP': _host,
                        'PORT': client.port,
                        'SALT': client.salt,
                        'RADIO_ID': str(int(ahex(_radio_id), 16)),
                        'CALLSIGN': _data[8:16],
                        'RX_FREQ': _data[16:25],
                        'TX_FREQ': _data[25:34],
                        'TX_POWER': _data[34:36],
                        'COLORCODE': _data[36:38],
                        'LATITUDE': _data[38:46],
                        'LONGITUDE': _data[46:55],
                        'HEIGHT': _data[55:58],
                        'LOCATION': _data[58:78],
                        'DESCRIPTION': _data[78:97],
                        'SLOTS': _data[97:98],
                        'URL': _data[98:222],
                        'SOFTWARE_ID': _data[222:262],
                        'PACKAGE_ID': _data[262:302],
                        'TG': client.tg,
                    }})

                    _this_client = self._clients[_radio_id]

                    try:
                        client_info = get_client_info(sqldb, _host, int(ahex(_radio_id), 16))
                        client_info.callsign = _this_client['CALLSIGN']
                        client_info.rx_freq = _this_client['RX_FREQ']
                        client_info.tx_freq = _this_client['TX_FREQ']
                        client_info.tx_power = _this_client['TX_POWER']
                        client_info.colorcode = int(_this_client['COLORCODE'])
                        client_info.latitude = float(_this_client['LATITUDE'])
                        client_info.longitude = float(_this_client['LONGITUDE'])
                        client_info.height = float(_this_client['HEIGHT'])
                        client_info.location = _this_client['LOCATION']
                        client_info.description = _this_client['DESCRIPTION']
                        client_info.slots = int(_this_client['SLOTS'])
                        client_info.url = _this_client['URL']
                        client_info.software_id = _this_client['SOFTWARE_ID']
                        client_info.package_id = _this_client['PACKAGE_ID']
                        client_info.ip_address = _host
                        client_info.radio_id = int(ahex(_radio_id), 16)
                        sqldb.commit()
                    except Exception as e:
                        self._logger.warning('Error getting client info for %s from %s %s', str(int(ahex(_radio_id), 16)), _host, e)

                    _this_client['CONNECTION'] = 'YES'
                    _this_client['LAST_PING'] = time()
                    client.connection = _this_client['CONNECTION']
                    client.last_ping = _this_client['LAST_PING']
                    sqldb.commit()

                    self.send_client(_radio_id, 'RPTACK'+_radio_id)
                    self._logger.info('(%s) Client %s (%s) has sent repeater configuration', self._system, _this_client['CALLSIGN'], _this_client['RADIO_ID'])

                elif _radio_id in self._clients \
                            and self._clients[_radio_id]['CONNECTION'] == 'WAITING_CONFIG' \
                            and self._clients[_radio_id]['IP'] == _host \
                            and self._clients[_radio_id]['PORT'] == _port:
                    _this_client = self._clients[_radio_id]
                    _this_client['CONNECTION'] = 'YES'
                    _this_client['LAST_PING'] = time()
                    _this_client['CALLSIGN'] = _data[8:16]
                    _this_client['RX_FREQ'] = _data[16:25]
                    _this_client['TX_FREQ'] =  _data[25:34]
                    _this_client['TX_POWER'] = _data[34:36]
                    _this_client['COLORCODE'] = _data[36:38]
                    _this_client['LATITUDE'] = _data[38:46]
                    _this_client['LONGITUDE'] = _data[46:55]
                    _this_client['HEIGHT'] = _data[55:58]
                    _this_client['LOCATION'] = _data[58:78]
                    _this_client['DESCRIPTION'] = _data[78:97]
                    _this_client['SLOTS'] = _data[97:98]
                    _this_client['URL'] = _data[98:222]
                    _this_client['SOFTWARE_ID'] = _data[222:262]
                    _this_client['PACKAGE_ID'] = _data[262:302]
                    _this_client['TG'] = client.tg
                    client.connection = _this_client['CONNECTION']
                    client.last_ping = _this_client['LAST_PING']
                    sqldb.commit()

                    try:
                        client_info = get_client_info(sqldb, _host, int(ahex(_radio_id), 16))
                        client_info.callsign = _this_client['CALLSIGN']
                        client_info.rx_freq = _this_client['RX_FREQ']
                        client_info.tx_freq = _this_client['TX_FREQ']
                        client_info.tx_power = _this_client['TX_POWER']
                        client_info.colorcode = int(_this_client['COLORCODE'])
                        client_info.latitude = float(_this_client['LATITUDE'])
                        client_info.longitude = float(_this_client['LONGITUDE'])
                        client_info.height = float(_this_client['HEIGHT'])
                        client_info.location = _this_client['LOCATION']
                        client_info.description = _this_client['DESCRIPTION']
                        client_info.slots = int(_this_client['SLOTS'])
                        client_info.url = _this_client['URL']
                        client_info.software_id = _this_client['SOFTWARE_ID']
                        client_info.package_id = _this_client['PACKAGE_ID']
                        client_info.ip_address = _host
                        client_info.radio_id = int(ahex(_radio_id), 16)
                        sqldb.commit()
                    except Exception as e:
                        self._logger.warning('Error getting client info for %s from %s %s', str(int(ahex(_radio_id), 16)), _host, e)

                    self.send_client(_radio_id, 'RPTACK'+_radio_id)
                    self._logger.info('(%s) Client %s (%s) has sent repeater configuration', self._system, _this_client['CALLSIGN'], _this_client['RADIO_ID'])
                else:
                    self.transport.write('MSTNAK'+_radio_id, (_host, _port))
                    self._logger.warning('(%s) Client info from Radio ID that has not logged in: %s', self._system, int_id(_radio_id))

        elif _command == 'RPTP':    # RPTPing -- client is pinging us
                _radio_id = _data[7:11]
                client = try_find_client(sqldb, db.ip2long(_host), int(ahex(_radio_id), 16))
                if _radio_id and self.check_dmrid(int(ahex(_radio_id), 16)): 
                    if _radio_id in self._clients \
                                and self._clients[_radio_id]['CONNECTION'] == "YES" \
                                and self._clients[_radio_id]['IP'] == _host \
                                and self._clients[_radio_id]['PORT'] == _port:
                        self._clients[_radio_id]['LAST_PING'] = time()
                        client.last_ping = self._clients[_radio_id]['LAST_PING']
                        sqldb.commit()
                        self.send_client(_radio_id, 'MSTPONG'+_radio_id)
                        self._logger.debug('(%s) Received and answered RPTPING from client %s (%s)', self._system, self._clients[_radio_id]['CALLSIGN'], int_id(_radio_id))
                    elif client:
                        self._clients.update({_radio_id: {      # Build the configuration data strcuture for the client
                            'CONNECTION': 'YES',
                            'PINGS_RECEIVED': 0,
                            'LAST_PING': time(),
                            'IP': _host,
                            'PORT': client.port,
                            'SALT': client.salt,
                            'RADIO_ID': str(int(ahex(_radio_id), 16)),
                            'CALLSIGN': 'TEST',
                            'RX_FREQ': '',
                            'TX_FREQ': '',
                            'TX_POWER': '',
                            'COLORCODE': '',
                            'LATITUDE': '',
                            'LONGITUDE': '',
                            'HEIGHT': '',
                            'LOCATION': '',
                            'DESCRIPTION': '',
                            'SLOTS': '',
                            'URL': '',
                            'SOFTWARE_ID': '',
                            'PACKAGE_ID': '',
                            'TG': client.tg,
                        }})
                    else:
                        self.transport.write('MSTNAK'+_radio_id, (_host, _port))
                        self._logger.warning('(%s) RPTPING from Radio ID that has not logged in: %s', self._system, int_id(_radio_id))

        else:
            self._logger.error('(%s) Unrecognized command. Raw HBP PDU: %s', self._system, ahex(_data))
        sqldb.flush()
        sqldb.close()
        
    # Aliased in __init__ to datagramReceived if system is a client
    def client_datagramReceived(self, _data, (_host, _port)):
        # Keep This Line Commented Unless HEAVILY Debugging!
        # self._logger.debug('(%s) RX packet from %s:%s -- %s', self._system, _host, _port, ahex(_data))

        # Validate that we receveived this packet from the master - security check!
        if self._config['MASTER_IP'] == _host and self._config['MASTER_PORT'] == _port:
            # Extract the command, which is various length, but only 4 significant characters
            _command = _data[:4]
            if   _command == 'DMRD':    # DMRData -- encapsulated DMR data frame
                _radio_id = _data[11:15]
                if self._config['LOOSE'] or _radio_id == self._config['RADIO_ID']: # Validate the Radio_ID unless using loose validation
                    _seq = _data[4:5]
                    _rf_src = _data[5:8]
                    _dst_id = _data[8:11]
                    _bits = int_id(_data[15])
                    _slot = 2 if (_bits & 0x80) else 1
                    _call_type = 'unit' if (_bits & 0x40) else 'group'
                    _frame_type = (_bits & 0x30) >> 4
                    _dtype_vseq = (_bits & 0xF) # data, 1=voice header, 2=voice terminator; voice, 0=burst A ... 5=burst F
                    _stream_id = _data[16:20]
                    #self._logger.debug('(%s) DMRD - Seqence: %s, RF Source: %s, Destination ID: %s', self._system, int_id(_seq), int_id(_rf_src), int_id(_dst_id))

                    # If AMBE audio exporting is configured...
                    if self._config['EXPORT_AMBE']:
                        self._ambe.parseAMBE(self._system, _data)

                    # Userland actions -- typically this is the function you subclass for an application
                    self.dmrd_received(_radio_id, _rf_src, _dst_id, _seq, _slot, _call_type, _frame_type, _dtype_vseq, _stream_id, _data)
                else:
                    if (ord(_data[15]) & 0x2F) == 0x21: # call initiator flag?
                        self._logger.warning('(%s) Packet received for wrong RADIO_ID.  Got %d should be %d', self._system, int_id(_radio_id), int_id(self._config['RADIO_ID']))

            elif _command == 'MSTN':    # Actually MSTNAK -- a NACK from the master
                _radio_id = _data[6:10] #
                if self._config['LOOSE'] or _radio_id == self._config['RADIO_ID']: # Validate the Radio_ID unless using loose validation
                    self._logger.warning('(%s) MSTNAK Received. Resetting connection to the Master.', self._system)
                    self._stats['CONNECTION'] = 'NO' # Disconnect ourselves and re-register
                else:
                    self._logger.debug('(%s) MSTNAK contained wrong ID - Ignoring', self._system)

            elif _command == 'RPTA':    # Actually RPTACK -- an ACK from the master
                # Depending on the state, an RPTACK means different things, in each clause, we check and/or set the state
                if self._stats['CONNECTION'] == 'RPTL_SENT': # If we've sent a login request...
                    _login_int32 = _data[6:10]
                    self._logger.info('(%s) Repeater Login ACK Received with 32bit ID: %s', self._system, int_id(_login_int32))
                    _pass_hash = sha256(_login_int32+self._config['PASSPHRASE']).hexdigest()
                    _pass_hash = bhex(_pass_hash)
                    self.send_master('RPTK'+self._config['RADIO_ID']+_pass_hash)
                    self._stats['CONNECTION'] = 'AUTHENTICATED'


                elif self._stats['CONNECTION'] == 'AUTHENTICATED': # If we've sent the login challenge...
                    _radio_id = _data[6:10]
                    if self._config['LOOSE'] or _radio_id == self._config['RADIO_ID']: # Validate the Radio_ID unless using loose validation
                        self._logger.info('(%s) Repeater Authentication Accepted', self._system)
                        _config_packet =  self._config['RADIO_ID']+\
                                          self._config['CALLSIGN']+\
                                          self._config['RX_FREQ']+\
                                          self._config['TX_FREQ']+\
                                          self._config['TX_POWER']+\
                                          self._config['COLORCODE']+\
                                          self._config['LATITUDE']+\
                                          self._config['LONGITUDE']+\
                                          self._config['HEIGHT']+\
                                          self._config['LOCATION']+\
                                          self._config['DESCRIPTION']+\
                                          self._config['SLOTS']+\
                                          self._config['URL']+\
                                          self._config['SOFTWARE_ID']+\
                                          self._config['PACKAGE_ID']

                        self.send_master('RPTC'+_config_packet)
                        self._stats['CONNECTION'] = 'CONFIG-SENT'
                        self._logger.info('(%s) Repeater Configuration Sent', self._system)
                    else:
                        self._stats['CONNECTION'] = 'NO'
                        self._logger.error('(%s) Master ACK Contained wrong ID - Connection Reset', self._system)

                elif self._stats['CONNECTION'] == 'CONFIG-SENT': # If we've sent out configuration to the master
                    _radio_id = _data[6:10]
                    if self._config['LOOSE'] or _radio_id == self._config['RADIO_ID']: # Validate the Radio_ID unless using loose validation
                        if self._config['OPTIONS']:
                            self.send_master('RPTO'+self._config['RADIO_ID']+self._config['OPTIONS'])
                            self._stats['CONNECTION'] = 'OPTIONS-SENT'
                            self._logger.info('(%s) Sent options: (%s)', self._system, self._config['OPTIONS'])
                        else:
                            self._stats['CONNECTION'] = 'YES'
                            self._logger.info('(%s) Connection to Master Completed', self._system)
                    else:
                        self._stats['CONNECTION'] = 'NO'
                        self._logger.error('(%s) Master ACK Contained wrong ID - Connection Reset', self._system)

                elif self._stats['CONNECTION'] == 'OPTIONS-SENT': # If we've sent out options to the master
                    _radio_id = _data[6:10]
                    if self._config['LOOSE'] or _radio_id == self._config['RADIO_ID']: # Validate the Radio_ID unless using loose validation
                        self._logger.info('(%s) Repeater Options Accepted', self._system)
                        self._stats['CONNECTION'] = 'YES'
                        self._logger.info('(%s) Connection to Master Completed with options', self._system)
                    else:
                        self._stats['CONNECTION'] = 'NO'
                        self._logger.error('(%s) Master ACK Contained wrong ID - Connection Reset', self._system)

            elif _command == 'MSTP':    # Actually MSTPONG -- a reply to RPTPING (send by client)
                _radio_id = _data[7:11]
                if self._config['LOOSE'] or _radio_id == self._config['RADIO_ID']: # Validate the Radio_ID unless using loose validation
                    self._stats['PING_OUTSTANDING'] = False
                    self._stats['NUM_OUTSTANDING'] = 0
                    self._stats['PINGS_ACKD'] += 1
                    self._logger.debug('(%s) MSTPONG Received. Pongs Since Connected: %s', self._system, self._stats['PINGS_ACKD'])
                else:
                    self._logger.debug('(%s) MSTPONG contained wrong ID - Ignoring', self._system)

            elif _command == 'MSTC':    # Actually MSTCL -- notify us the master is closing down
                _radio_id = _data[5:9]
                if self._config['LOOSE'] or _radio_id == self._config['RADIO_ID']: # Validate the Radio_ID unless using loose validation
                    self._stats['CONNECTION'] = 'NO'
                    self._logger.info('(%s) MSTCL Recieved', self._system)
                else:
                    self._logger.debug('(%s) MSTCL contained wrong ID - Ignoring', self._system)

            else:
                self._logger.error('(%s) Received an invalid command in packet: %s', self._system, ahex(_data))

class report(NetstringReceiver):
    def __init__(self, factory):
        self._factory = factory

    def connectionMade(self):
        self._factory.clients.append(self)
        self._factory._logger.info('HBlink reporting client connected: %s', self.transport.getPeer())

    def connectionLost(self, reason):
        self._factory._logger.info('HBlink reporting client disconnected: %s', self.transport.getPeer())
        self._factory.clients.remove(self)

    def stringReceived(self, data):
        self.process_message(data)

    def process_message(self, _message):
        opcode = _message[:1]
        if opcode == REPORT_OPCODES['CONFIG_REQ']:
            self._factory._logger.info('HBlink reporting client sent \'CONFIG_REQ\': %s', self.transport.getPeer())
            self.send_config()
        else:
            self._factory._logger.error('got unknown opcode')
        
class reportFactory(Factory):
    def __init__(self, config, logger):
        self._config = config
        self._logger = logger
        
    def buildProtocol(self, addr):
        if (addr.host) in self._config['REPORTS']['REPORT_CLIENTS'] or '*' in self._config['REPORTS']['REPORT_CLIENTS']:
            self._logger.debug('Permitting report server connection attempt from: %s:%s', addr.host, addr.port)
            return report(self)
        else:
            self._logger.error('Invalid report server connection attempt from: %s:%s', addr.host, addr.port)
            return None
            
    def send_clients(self, _message):
        for client in self.clients:
            client.sendString(_message)
            
    def send_config(self):
        serialized = pickle.dumps(self._config['SYSTEMS'], protocol=pickle.HIGHEST_PROTOCOL)
        self.send_clients(REPORT_OPCODES['CONFIG_SND']+serialized)

#************************************************
#      MAIN PROGRAM LOOP STARTS HERE
#************************************************

if __name__ == '__main__':
    # Python modules we need
    import argparse
    import sys
    import os
    import signal
    
    
    # Change the current directory to the location of the application
    os.chdir(os.path.dirname(os.path.realpath(sys.argv[0])))

    # CLI argument parser - handles picking up the config file from the command line, and sending a "help" message
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', action='store', dest='CONFIG_FILE', help='/full/path/to/config.file (usually hblink.cfg)')
    parser.add_argument('-l', '--logging', action='store', dest='LOG_LEVEL', help='Override config file logging level.')
    cli_args = parser.parse_args()

    # Ensure we have a path for the config file, if one wasn't specified, then use the execution directory
    if not cli_args.CONFIG_FILE:
        cli_args.CONFIG_FILE = os.path.dirname(os.path.abspath(__file__))+'/hblink.cfg'

    # Call the external routine to build the configuration dictionary
    CONFIG = hb_config.build_config(cli_args.CONFIG_FILE)
    
    # Call the external routing to start the system logger
    if cli_args.LOG_LEVEL:
        CONFIG['LOGGER']['LOG_LEVEL'] = cli_args.LOG_LEVEL
    logger = hb_log.config_logging(CONFIG['LOGGER'])
    logger.debug('Logging system started, anything from here on gets logged')

    # Set up the signal handler
    def sig_handler(_signal, _frame):
        logger.info('SHUTDOWN: HBLINK IS TERMINATING WITH SIGNAL %s', str(_signal))
        hblink_handler(_signal, _frame, logger)
        logger.info('SHUTDOWN: ALL SYSTEM HANDLERS EXECUTED - STOPPING REACTOR')
        reactor.stop()
        
    # Set signal handers so that we can gracefully exit if need be
    for sig in [signal.SIGTERM, signal.SIGINT]:
        signal.signal(sig, sig_handler)

    report_server = config_reports(CONFIG, logger, reportFactory) 

    # HBlink instance creation
    logger.info('HBlink \'HBlink.py\' (c) 2016 N0MJS & the K0USY Group - SYSTEM STARTING...')
    for system in CONFIG['SYSTEMS']:
        if CONFIG['SYSTEMS'][system]['ENABLED']:
            systems[system] = HBSYSTEM(system, CONFIG, logger, report_server)
            reactor.listenUDP(CONFIG['SYSTEMS'][system]['PORT'], systems[system], interface=CONFIG['SYSTEMS'][system]['IP'])
            logger.debug('%s instance created: %s, %s', CONFIG['SYSTEMS'][system]['MODE'], system, systems[system])

    reactor.run()
