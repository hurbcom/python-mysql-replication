# -*- coding: utf-8 -*-

import struct

from logging import getLogger
from pymysql.util import byte2int

from pymysqlreplication import constants, event, row_event
from pymysqlreplication.protocol import StructMysql

log = getLogger(__name__)

# Constants from PyMYSQL source code
UNSIGNED_CHAR_LENGTH = 1


class BinLogPacketWrapper(StructMysql):
    """
    Bin Log Packet Wrapper. It uses an existing packet object, and wraps
    around it, exposing useful variables while still providing access
    to the original packet objects variables and methods.
    """

    __event_map = {
        # event
        constants.QUERY_EVENT: event.QueryEvent,
        constants.ROTATE_EVENT: event.RotateEvent,
        constants.FORMAT_DESCRIPTION_EVENT: event.FormatDescriptionEvent,
        constants.XID_EVENT: event.XidEvent,
        constants.INTVAR_EVENT: event.IntvarEvent,
        constants.GTID_LOG_EVENT: event.GtidEvent,
        constants.STOP_EVENT: event.StopEvent,
        constants.BEGIN_LOAD_QUERY_EVENT: event.BeginLoadQueryEvent,
        constants.EXECUTE_LOAD_QUERY_EVENT: event.ExecuteLoadQueryEvent,
        constants.HEARTBEAT_LOG_EVENT: event.HeartbeatLogEvent,
        constants.XA_PREPARE_EVENT: event.XAPrepareEvent,
        # row_event
        constants.UPDATE_ROWS_EVENT_V1: row_event.UpdateRowsEvent,
        constants.WRITE_ROWS_EVENT_V1: row_event.WriteRowsEvent,
        constants.DELETE_ROWS_EVENT_V1: row_event.DeleteRowsEvent,
        constants.UPDATE_ROWS_EVENT_V2: row_event.UpdateRowsEvent,
        constants.WRITE_ROWS_EVENT_V2: row_event.WriteRowsEvent,
        constants.DELETE_ROWS_EVENT_V2: row_event.DeleteRowsEvent,
        constants.TABLE_MAP_EVENT: row_event.TableMapEvent,
        #5.6 GTID enabled replication events
        constants.ANONYMOUS_GTID_LOG_EVENT: event.NotImplementedEvent,
        constants.PREVIOUS_GTIDS_LOG_EVENT: event.NotImplementedEvent

    }

    def __init__(self, from_packet, table_map,
                 ctl_connection,
                 mysql_version,
                 use_checksum,
                 allowed_events,
                 only_tables,
                 ignored_tables,
                 only_schemas,
                 ignored_schemas,
                 freeze_schema,
                 fail_on_table_metadata_unavailable):
        # -1 because we ignore the ok byte
        self.read_bytes = 0
        # Used when we want to override a value in the data buffer
        self.data_buffer = b''

        self.packet = from_packet
        self.charset = ctl_connection.charset

        # OK value
        # timestamp
        # event_type
        # server_id
        # log_pos
        # flags
        unpack = struct.unpack('<cIcIIIH', self.packet.read(20))

        # Header
        self.timestamp = unpack[1]
        self.event_type = byte2int(unpack[2])
        self.server_id = unpack[3]
        self.event_size = unpack[4]
        # position of the next event
        self.log_pos = unpack[5]
        self.flags = unpack[6]

        # MySQL 5.6 and more if binlog-checksum = CRC32
        if use_checksum:
            event_size_without_header = self.event_size - 23
        else:
            event_size_without_header = self.event_size - 19

        self.event = None
        event_class = self.__event_map.get(self.event_type, event.NotImplementedEvent)

        if event_class not in allowed_events:
            return
        self.event = event_class(self, event_size_without_header, table_map,
                                 ctl_connection,
                                 mysql_version=mysql_version,
                                 only_tables=only_tables,
                                 ignored_tables=ignored_tables,
                                 only_schemas=only_schemas,
                                 ignored_schemas=ignored_schemas,
                                 freeze_schema=freeze_schema,
                                 fail_on_table_metadata_unavailable=fail_on_table_metadata_unavailable)
        if self.event._processed == False:
            self.event = None

    def read(self, size):
        size = int(size)
        self.read_bytes += size
        if len(self.data_buffer) > 0:
            data = self.data_buffer[:size]
            self.data_buffer = self.data_buffer[size:]
            if len(data) == size:
                return data
            else:
                return data + self.packet.read(size - len(data))
        return self.packet.read(size)

    def unread(self, data):
        '''Push again data in data buffer. It's use when you want
        to extract a bit from a value a let the rest of the code normally
        read the datas'''
        self.read_bytes -= len(data)
        self.data_buffer += data

    def advance(self, size):
        size = int(size)
        self.read_bytes += size
        buffer_len = len(self.data_buffer)
        if buffer_len > 0:
            self.data_buffer = self.data_buffer[size:]
            if size > buffer_len:
                self.packet.advance(size - buffer_len)
        else:
            self.packet.advance(size)

    def __getattr__(self, key):
        if hasattr(self.packet, key):
            return getattr(self.packet, key)

        raise AttributeError("%s instance has no attribute '%s'" %
                             (self.__class__, key))
