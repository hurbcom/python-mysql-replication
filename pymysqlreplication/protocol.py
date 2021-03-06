import decimal
import struct
import logging

log = logging.getLogger(__name__)

from pymysql.util import byte2int

from .constants import *


class StructMysql(object):
    def read(self, size):
        return ''

    def read_length_coded_binary(self):
        """Read a 'Length Coded Binary' number from the data buffer.

        Length coded numbers can be anywhere from 1 to 9 bytes depending
        on the value of the first byte.

        From PyMYSQL source code
        """
        c = byte2int(self.read(1))
        if c == NULL_COLUMN:
            return None
        if c < UNSIGNED_CHAR_COLUMN:
            return c
        elif c == UNSIGNED_SHORT_COLUMN:
            return self.unpack_uint16(self.read(UNSIGNED_SHORT_LENGTH))
        elif c == UNSIGNED_INT24_COLUMN:
            return self.unpack_int24(self.read(UNSIGNED_INT24_LENGTH))
        elif c == UNSIGNED_INT64_COLUMN:
            return self.unpack_int64(self.read(UNSIGNED_INT64_LENGTH))

    def read_length_coded_string(self):
        """Read a 'Length Coded String' from the data buffer.

        A 'Length Coded String' consists first of a length coded
        (unsigned, positive) integer represented in 1-9 bytes followed by
        that many bytes of binary data.  (For example "cat" would be "3cat".)

        From PyMYSQL source code
        """
        length = self.read_length_coded_binary()
        if length is None:
            return None
        return self.read(length).decode()

    def read_int_be_by_size(self, size):
        '''Read a big endian integer values based on byte number'''
        if size == 1:
            return struct.unpack('>b', self.read(size))[0]
        elif size == 2:
            return struct.unpack('>h', self.read(size))[0]
        elif size == 3:
            return self.read_int24_be()
        elif size == 4:
            return struct.unpack('>i', self.read(size))[0]
        elif size == 5:
            return self.read_int40_be()
        elif size == 8:
            return struct.unpack('>l', self.read(size))[0]

    def read_uint_by_size(self, size):
        '''Read a little endian integer values based on byte number'''
        if size == 1:
            return self.read_uint8()
        elif size == 2:
            return self.read_uint16()
        elif size == 3:
            return self.read_uint24()
        elif size == 4:
            return self.read_uint32()
        elif size == 5:
            return self.read_uint40()
        elif size == 6:
            return self.read_uint48()
        elif size == 7:
            return self.read_uint56()
        elif size == 8:
            return self.read_uint64()

    def read_length_coded_pascal_string(self, size):
        """Read a string with length coded using pascal style.
        The string start by the size of the string
        """
        length = self.read_uint_by_size(size)
        return self.read(length)

    def read_variable_length_string(self):
        """Read a variable length string where the first 1-5 bytes stores the
        length of the string.

        For each byte, the first bit being high indicates another byte must be
        read.
        """
        byte = 0x80
        length = 0
        bits_read = 0
        while byte & 0x80 != 0:
            byte = byte2int(self.read(1))
            length = length | ((byte & 0x7f) << bits_read)
            bits_read = bits_read + 7
        return self.read(length)

    def read_int24(self):
        a, b, c = struct.unpack("BBB", self.read(3))
        res = a | (b << 8) | (c << 16)
        if res >= 0x800000:
            res -= 0x1000000
        return res

    def read_int24_be(self):
        a, b, c = struct.unpack('BBB', self.read(3))
        res = (a << 16) | (b << 8) | c
        if res >= 0x800000:
            res -= 0x1000000
        return res

    def read_uint8(self):
        return struct.unpack('<B', self.read(1))[0]

    def read_int16(self):
        return struct.unpack('<h', self.read(2))[0]

    def read_uint16(self):
        return struct.unpack('<H', self.read(2))[0]

    def read_uint24(self):
        a, b, c = struct.unpack("<BBB", self.read(3))
        return a + (b << 8) + (c << 16)

    def read_uint32(self):
        return struct.unpack('<I', self.read(4))[0]

    def read_int32(self):
        return struct.unpack('<i', self.read(4))[0]

    def read_uint40(self):
        a, b = struct.unpack("<BI", self.read(5))
        return a + (b << 8)

    def read_int40_be(self):
        a, b = struct.unpack(">IB", self.read(5))
        return b + (a << 8)

    def read_uint48(self):
        a, b, c = struct.unpack("<HHH", self.read(6))
        return a + (b << 16) + (c << 32)

    def read_uint56(self):
        a, b, c = struct.unpack("<BHI", self.read(7))
        return a + (b << 8) + (c << 24)

    def read_uint64(self):
        return struct.unpack('<Q', self.read(8))[0]

    def read_int64(self):
        return struct.unpack('<q', self.read(8))[0]

    def unpack_uint16(self, n):
        return struct.unpack('<H', n[0:2])[0]

    def unpack_int24(self, n):
        try:
            return struct.unpack('B', n[0])[0] \
                + (struct.unpack('B', n[1])[0] << 8) \
                + (struct.unpack('B', n[2])[0] << 16)
        except TypeError:
            return n[0] + (n[1] << 8) + (n[2] << 16)

    def unpack_int32(self, n):
        try:
            return struct.unpack('B', n[0])[0] \
                + (struct.unpack('B', n[1])[0] << 8) \
                + (struct.unpack('B', n[2])[0] << 16) \
                + (struct.unpack('B', n[3])[0] << 24)
        except TypeError:
            return n[0] + (n[1] << 8) + (n[2] << 16) + (n[3] << 24)

    def unpack_int64(self, n):
        try:
            return struct.unpack('B', n[0])[0] \
                + (struct.unpack('B', n[1])[0] << 8) \
                + (struct.unpack('B', n[2])[0] << 16) \
                + (struct.unpack('B', n[3])[0] << 24) \
                + (struct.unpack('B', n[4])[0] << 32)
        except TypeError:
            return n[0] + (n[1] << 8) + (n[2] << 16) + (n[3] << 24) + (n[4] << 32)


class WrapperPayload(StructMysql):
    def __init__(self, payload):
        self.payload = payload
        self.point = 0

    def read(self, size):
        self.point += size
        return self.payload[self.point-size:self.point]

    def advance(self, size):
        self.point += size

    def rewind(self, size):
        self.point -= size


class WrapperJson(WrapperPayload):
    def read_binary_json_type(self, t, length):
        large = (t in (JSONB_TYPE_LARGE_OBJECT, JSONB_TYPE_LARGE_ARRAY))
        if t in (JSONB_TYPE_SMALL_OBJECT, JSONB_TYPE_LARGE_OBJECT):
            return self.read_binary_json_object(length - 1, large)
        elif t in (JSONB_TYPE_SMALL_ARRAY, JSONB_TYPE_LARGE_ARRAY):
            return self.read_binary_json_array(length - 1, large)
        elif t in (JSONB_TYPE_STRING,):
            return self.read_variable_length_string()
        elif t in (JSONB_TYPE_LITERAL,):
            value = self.read_uint8()
            if value == JSONB_LITERAL_NULL:
                return None
            elif value == JSONB_LITERAL_TRUE:
                return True
            elif value == JSONB_LITERAL_FALSE:
                return False
        elif t == JSONB_TYPE_INT16:
            return self.read_int16()
        elif t == JSONB_TYPE_UINT16:
            return self.read_uint16()
        elif t in (JSONB_TYPE_DOUBLE,):
            return struct.unpack('<d', self.read(8))[0]
        elif t == JSONB_TYPE_INT32:
            return self.read_int32()
        elif t == JSONB_TYPE_UINT32:
            return self.read_uint32()
        elif t == JSONB_TYPE_INT64:
            return self.read_int64()
        elif t == JSONB_TYPE_UINT64:
            return self.read_uint64()
        elif t == JSONB_TYPE_OPAQUE:
            return self.read_opaque(length)

        raise ValueError('Json type %d is not handled' % t)

    def read_opaque(self, length):
        t = self.read_uint8()
        if t == 246:
            return self.read_new_decimal()

        raise ValueError('Json Opaque type %d is not handled' % t)

    def read_new_decimal(self):
        precision = self.read_uint8()
        decimals = self.read_uint8()
        """Read MySQL's new decimal format introduced in MySQL 5"""

        # This project was a great source of inspiration for
        # understanding this storage format.
        # https://github.com/jeremycole/mysql_binlog

        digits_per_integer = 9
        compressed_bytes = [0, 1, 1, 2, 2, 3, 3, 4, 4, 4]
        integral = (precision - decimals)
        uncomp_integral = int(integral / digits_per_integer)
        uncomp_fractional = int(decimals / digits_per_integer)
        comp_integral = integral - (uncomp_integral * digits_per_integer)
        comp_fractional = decimals - (uncomp_fractional
                                             * digits_per_integer)

        # Support negative
        # The sign is encoded in the high bit of the the byte
        # But this bit can also be used in the value
        value = self.read_uint8()
        if value & 0x80 != 0:
            res = ""
            mask = 0
        else:
            mask = -1
            res = "-"
        self.unread(struct.pack('<B', value ^ 0x80))

        size = compressed_bytes[comp_integral]
        if size > 0:
            value = self.read_int_be_by_size(size) ^ mask
            res += str(value)

        for i in range(0, uncomp_integral):
            value = struct.unpack('>i', self.read(4))[0] ^ mask
            res += '%09d' % value

        res += "."

        for i in range(0, uncomp_fractional):
            value = struct.unpack('>i', self.read(4))[0] ^ mask
            res += '%09d' % value

        size = compressed_bytes[comp_fractional]
        if size > 0:
            value = self.read_int_be_by_size(size) ^ mask
            res += '%0*d' % (comp_fractional, value)

        return decimal.Decimal(res)

    def read_binary_json_type_inlined(self, t, large):
        if t == JSONB_TYPE_LITERAL:
            value = self.read_uint32() if large else self.read_uint16()
            if value == JSONB_LITERAL_NULL:
                return None
            elif value == JSONB_LITERAL_TRUE:
                return True
            elif value == JSONB_LITERAL_FALSE:
                return False
        elif t == JSONB_TYPE_INT16:
            return self.read_int16()
        elif t == JSONB_TYPE_UINT16:
            return self.read_uint16()
        elif t == JSONB_TYPE_INT32:
            return self.read_int32()
        elif t == JSONB_TYPE_UINT32:
            return self.read_uint32()
        elif t == JSONB_TYPE_INT64:
            return self.read_int64()
        elif t == JSONB_TYPE_UINT64:
            return self.read_uint64()
        raise ValueError('Json type %d is not handled' % t)

    def read_binary_json_object(self, length, large):
        if large:
            elements = self.read_uint32()
            size = self.read_uint32()
        else:
            elements = self.read_uint16()
            size = self.read_uint16()

        if size > length:
            raise ValueError('Json length is larger than packet length')

        if large:
            key_offset_lengths = [(
                self.read_uint32()+1,  # offset (we don't actually need that)
                self.read_uint16()   # size of the key
                ) for _ in range(elements)]
        else:
            key_offset_lengths = [(
                self.read_uint16()+1,  # offset (we don't actually need that)
                self.read_uint16()   # size of key
                ) for _ in range(elements)]

        value_type_inlined_lengths = [read_offset_or_inline(self, large)
                                      for _ in range(elements)]

        if key_offset_lengths[0][0] > self.point:
            self.point = key_offset_lengths[0][0]

        keys = [self.read(x[1]) for x in key_offset_lengths]

        # keys = [self.payload[x[0]:x[0]+x[1]] for x in key_offset_lengths]
        # self.point = key_offset_lengths[-1][0] + key_offset_lengths[-1][1]
        # print(value_type_inlined_lengths)
        # print("elements0: %d, size: %d, large: %d" % (elements, size, large))

        out = {}

        for i in range(elements):
            key = keys[i]
            field = value_type_inlined_lengths[i]
            if field[1] is None:
                data = field[2]
            else:
                try:
                    data = self.read_binary_json_type(field[0], length)
                except Exception as e:
                    # log.exception(e)
                    data = None

            out[key] = data

        return out

    def read_binary_json_array(self, length, large):
        if large:
            elements = self.read_uint32()
            size = self.read_uint32()
        else:
            elements = self.read_uint16()
            size = self.read_uint16()

        if size > length:
            raise ValueError('Json length is larger than packet length')

        values_type_offset_inline = [
            read_offset_or_inline(self, large)
            for _ in range(elements)]
        # print(values_type_offset_inline)
        # print("elements1: %d, size: %d, large: %d" %(elements, size, large))

        def _read(x):
            if x[1] is None:
                return x[2]
            return self.read_binary_json_type(x[0], length)

        return [_read(x) for x in values_type_offset_inline]


def read_offset_or_inline(packet, large):
    t = packet.read_uint8()

    if t in (JSONB_TYPE_LITERAL,
             JSONB_TYPE_INT16,
             JSONB_TYPE_UINT16):
        return t, None, packet.read_binary_json_type_inlined(t, large)

    if large and t in (JSONB_TYPE_INT32, JSONB_TYPE_UINT32):
        return t, None, packet.read_binary_json_type_inlined(t, large)

    if large:
        return t, packet.read_uint32(), None

    return t, packet.read_uint16(), None

