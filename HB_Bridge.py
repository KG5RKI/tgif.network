#!/usr/bin/env python
#
###############################################################################
#   Copyright (C) 2017 Mike Zingman N4IRR
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
'''

from __future__ import print_function

# Python modules we need
import sys
from bitarray import bitarray
from bitstring import BitArray
from bitstring import BitString
import struct
from time import time, sleep
from importlib import import_module
from binascii import b2a_hex as ahex
from random import randint
import sys, socket, ConfigParser, thread, traceback
from threading import Lock
from time import time, sleep, clock, localtime, strftime

# Twisted is pretty important, so I keep it separate
from twisted.internet.protocol import DatagramProtocol, Factory, Protocol
from twisted.internet import reactor
from twisted.protocols.basic import NetstringReceiver
from twisted.internet import task

# Things we import from the main hblink module
from hblink import HBSYSTEM, systems, int_id, hblink_handler
from dmr_utils.utils import hex_str_3, hex_str_4, int_id, get_alias
from dmr_utils import decode, bptc, const, golay, qr
import hb_config
import hb_log
import hb_const
from dmr_utils import ambe_utils
from dmr_utils.ambe_bridge import AMBE_HB

# Imports for the reporting server
import cPickle as pickle
from reporting_const import *

# Does anybody read this stuff? There's a PEP somewhere that says I should do this.
__author__     = 'Mike Zingman, N4IRR and Cortney T. Buffington, N0MJS'
__copyright__  = 'Copyright (c) 2017 Mike Zingman N4IRR'
__credits__    = 'Cortney T. Buffington, N0MJS; Colin Durbridge, G4EML, Steve Zingman, N4IRS; Jonathan Naylor, G4KLX; Hans Barthen, DL5DI; Torsten Shultze, DG1HT'
__license__    = 'GNU GPLv3'
__maintainer__ = 'Cort Buffington, N0MJS'
__email__      = 'n0mjs@me.com'
__status__     = 'pre-alpha'
__version__    = '20170620'

mutex = Lock()  # Used to synchronize Peer I/O in different threads

dmrd_last_ip = {}
dmrd_last_time = {}

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

class TRANSLATE:
    def __init__(self, config_file):
        self.translate = {}
        self.load_config(config_file)
        pass
    def add_rule( self, tg, export_rule):
        self.translate[str(tg)] = export_rule
        #print(int_id(tg), export_rule)
    def delete_rule(self, tg):
        if str(tg) in self.translate:
            del self.translate[str(tg)]
    def find_rule(self, tg, slot):
        if str(tg) in self.translate:
            return self.translate[str(tg)]
        #if talkgroup dst not in rules, do not forward to partners
        return (0, 0)
    def load_config(self, config_file):
        print('load config file', config_file)
        pass

# translation structure.  IMPORT_TO translates foreign (TG,TS) to local.  EXPORT_AS translates local (TG,TS) to foreign values
translate = TRANSLATE('config.file')

class HB_BRIDGE(HBSYSTEM):
    
    def __init__(self, _name, _config, _logger, report_server):
        HBSYSTEM.__init__(self, _name, _config, _logger, report_server)


        self._ambeRxPort = 31003        # Port to listen on for AMBE frames to transmit to all peers
        self._gateway = "127.0.0.1"     # IP address of Analog_Bridge app
        self._gateway_port = 31000      # Port Analog_Bridge is listening on for AMBE frames to decode
        
        

        self.load_configuration(cli_args.BRIDGE_CONFIG_FILE)

        self.hb_ambe = AMBE_HB(self, _name, _config, _logger, self._ambeRxPort)
        self._sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

    def get_globals(self):
        return (subscriber_ids, talkgroup_ids, peer_ids)

    def get_repeater_id(self, import_id):
        if self._config['MODE'] == 'CLIENT':    # only clients have radio_id defined, masters do not
            return self._config['RADIO_ID']
        return import_id

    # Load configuration from file
    def load_configuration( self, _file_name ):
        config = ConfigParser.ConfigParser()
        if not config.read(_file_name):
            sys.exit('Configuration file \''+_file_name+'\' is not a valid configuration file! Exiting...')
        try:
            for section in config.sections():
                if section == 'DEFAULTS':
                    self._ambeRxPort = int(config.get(section, 'fromGatewayPort').split(None)[0])           # Port to listen on for AMBE frames to transmit to all peers
                    self._gateway = config.get(section, 'gateway').split(None)[0]                           # IP address of Analog_Bridge app
                    self._gateway_port = int(config.get(section, 'toGatewayPort').split(None)[0])           # Port Analog_Bridge is listening on for AMBE frames to decode
                if section == 'RULES':
                    for rule in config.items(section):
                        _old_tg, _new_tg, _new_slot = rule[1].split(',')
                        translate.add_rule(hex_str_3(int(_old_tg)), (hex_str_3(int(_new_tg)), int(_new_slot)))

        except ConfigParser.Error, err:
            traceback.print_exc()
            sys.exit('Could not parse configuration file, ' + _file_name + ', exiting...')


    # HBLink callback with DMR data from perr/master.  Send this data to any partner listening
    def dmrd_received(self, _radio_id, _rf_src, _dst_id, _seq, _slot, _call_type, _frame_type, _dtype_vseq, _stream_id, _data):
        _dst_id, _slot = translate.find_rule(_dst_id,_slot)
        
		  #if dst talkgroup is not in rule set, do not forward data to partner applications        
        if _dst_id == 0:
            return		
        cur_time = time()
        client_ip = self.transport.getPeer()
        okgo = 0
        try:
            ind = str(int_id(_dst_id))
            if ind not in dmrd_last_ip:
            	dmrd_last_ip[ind] = client_ip

            if dmrd_last_ip[ind] != client_ip or _tx_slot.lastSeq != _seq:
               if ind not in dmrd_last_time:
               	dmrd_last_time[ind] = cur_time
               	self._logger.debug('dmrd new tg dest %s', ind)
               	okgo = 1
               elif cur_time > (cur_time - dmrd_last_time[ind] > 1.5):
               	dmrd_last_ip[ind] = client_ip
               	okgo = 1
               	self._logger.debug('dmrd_ > 3 %d', cur_time)
               else:
               	self._logger.debug('dmrd_last_ip %s', dmrd_last_ip[ind])
               
               	
            else:
               okgo = 1
            dmrd_last_time[ind] = cur_time
        except:
            okgo = 1
            self._logger.debug('Failed to get tg info for %d', int_id(_dst_id))
        #self._logger.debug('Failed to get tg info for %d', int_id(_dst_id))    
        if okgo == 1 and _rf_src != 310033 and _radio_id != 310033:
            _tx_slot = self.hb_ambe.tx[_slot]
            _seq = ord(_data[4])
            _tx_slot.frame_count += 1
            if (_stream_id != _tx_slot.stream_id):
               self.hb_ambe.begin_call(_slot, _rf_src, _dst_id, _radio_id, _tx_slot.cc, _seq, _stream_id)
               _tx_slot.lastSeq = _seq
            if (_frame_type == hb_const.HBPF_DATA_SYNC) and (_dtype_vseq == hb_const.HBPF_SLT_VTERM) and (_tx_slot.type != hb_const.HBPF_SLT_VTERM):
               self.hb_ambe.end_call(_tx_slot)
            if (int_id(_data[15]) & 0x20) == 0:
               _dmr_frame = BitArray('0x'+ahex(_data[20:]))
               _ambe = _dmr_frame[0:108] + _dmr_frame[156:264]
               self.hb_ambe.export_voice(_tx_slot, _seq, _ambe.tobytes())
               self._logger.debug('Exporting voice %d to %d', int_id(_seq), int_id(_dst_id))
            else:
               _tx_slot.lastSeq = _seq
        else:
        		self._logger.debug('Skipping transmit to %d', int_id(_dst_id))

    # The methods below are overridden becuse the launchUDP thread can also wite to a master or client async and confuse the master
    # A lock is used to synchronize the two threads so that the resource is protected
    def send_master(self, _packet):
        #mutex.acquire()
        HBSYSTEM.send_master(self, _packet)
        #mutex.release()
    
    def send_clients(self, _packet):
        #mutex.acquire()
        HBSYSTEM.send_clients(self, _packet)
        #mutex.release()


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


############################################################################################################
#      MAIN PROGRAM LOOP STARTS HERE
############################################################################################################

if __name__ == '__main__':
    
    import argparse
    import sys
    import os
    import signal
    from dmr_utils.utils import try_download, mk_id_dict
    
    # Change the current directory to the location of the application
    os.chdir(os.path.dirname(os.path.realpath(sys.argv[0])))

    # CLI argument parser - handles picking up the config file from the command line, and sending a "help" message
    # Added the capability to define a custom bridge config file, multiple bridges are needed when doing things like Analog_Bridge
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', action='store', dest='CONFIG_FILE', help='/full/path/to/config.file (default hblink.cfg)')
    parser.add_argument('-l', '--logging', action='store', dest='LOG_LEVEL', help='Override config file logging level.')
    parser.add_argument('-b','--bridge_config', action='store', dest='BRIDGE_CONFIG_FILE', help='/full/path/to/bridgeconfig.cfg (default HB_Bridge.cfg)')
    cli_args = parser.parse_args()

    # Ensure we have a path for the config file, if one wasn't specified, then use the default (top of file)
    if not cli_args.CONFIG_FILE:
        cli_args.CONFIG_FILE = os.path.dirname(os.path.abspath(__file__))+'/hblink.cfg'

    # Ensure we have a path for the bridge config file, if one wasn't specified, then use the default (top of file)
    if not cli_args.BRIDGE_CONFIG_FILE:
        cli_args.BRIDGE_CONFIG_FILE = os.path.dirname(os.path.abspath(__file__))+'/HB_Bridge.cfg'

    # Call the external routine to build the configuration dictionary
    CONFIG = hb_config.build_config(cli_args.CONFIG_FILE)
    
    # Start the system logger
    if cli_args.LOG_LEVEL:
        CONFIG['LOGGER']['LOG_LEVEL'] = cli_args.LOG_LEVEL
    logger = hb_log.config_logging(CONFIG['LOGGER'])
    logger.debug('Logging system started, anything from here on gets logged')
    
    # Set up the signal handler
    def sig_handler(_signal, _frame):
        logger.info('SHUTDOWN: HB_Bridge IS TERMINATING WITH SIGNAL %s', str(_signal))
        hblink_handler(_signal, _frame, logger)
        logger.info('SHUTDOWN: ALL SYSTEM HANDLERS EXECUTED - STOPPING REACTOR')
        reactor.stop()
        
    # Set signal handers so that we can gracefully exit if need be
    for sig in [signal.SIGTERM, signal.SIGINT]:
        signal.signal(sig, sig_handler)
    
    # ID ALIAS CREATION
    # Download
    if CONFIG['ALIASES']['TRY_DOWNLOAD'] == True:
        # Try updating peer aliases file
        result = try_download(CONFIG['ALIASES']['PATH'], CONFIG['ALIASES']['PEER_FILE'], CONFIG['ALIASES']['PEER_URL'], CONFIG['ALIASES']['STALE_TIME'])
        logger.info(result)
        # Try updating subscriber aliases file
        result = try_download(CONFIG['ALIASES']['PATH'], CONFIG['ALIASES']['SUBSCRIBER_FILE'], CONFIG['ALIASES']['SUBSCRIBER_URL'], CONFIG['ALIASES']['STALE_TIME'])
        logger.info(result)
        
    # Make Dictionaries
    peer_ids = mk_id_dict(CONFIG['ALIASES']['PATH'], CONFIG['ALIASES']['PEER_FILE'])
    if peer_ids:
        logger.info('ID ALIAS MAPPER: peer_ids dictionary is available')
        
    subscriber_ids = mk_id_dict(CONFIG['ALIASES']['PATH'], CONFIG['ALIASES']['SUBSCRIBER_FILE'])
    if subscriber_ids:
        logger.info('ID ALIAS MAPPER: subscriber_ids dictionary is available')
    
    talkgroup_ids = mk_id_dict(CONFIG['ALIASES']['PATH'], CONFIG['ALIASES']['TGID_FILE'])
    if talkgroup_ids:
        logger.info('ID ALIAS MAPPER: talkgroup_ids dictionary is available')
    
    report_server = config_reports(CONFIG, logger, reportFactory) 
    
    # HBlink instance creation
    logger.info('HBlink \'HB_Bridge.py\' (c) 2017 Mike Zingman N4IRR, N0MJS - SYSTEM STARTING...')
    logger.info('Version %s', __version__)
    for system in CONFIG['SYSTEMS']:
        if CONFIG['SYSTEMS'][system]['ENABLED']:
            systems[system] = HB_BRIDGE(system, CONFIG, logger, report_server)
            reactor.listenUDP(CONFIG['SYSTEMS'][system]['PORT'], systems[system], interface=CONFIG['SYSTEMS'][system]['IP'])
            logger.debug('%s instance created: %s, %s', CONFIG['SYSTEMS'][system]['MODE'], system, systems[system])

    reactor.run()
