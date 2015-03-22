import mmap
import struct

class Dexparser:

	def __init__(self, filedir):
		f = open(filedir, 'rb')
		m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

		self.mmap = m

		magic           = m[0:8]
		checksum        = struct.unpack('<L', m[8:0xC])[0]
		sa1             = m[0xC:0x20]
		file_size       = struct.unpack('<L', m[0x20:0x24])[0]
		header_size     = struct.unpack('<L', m[0x24:0x28])[0]
		endian_tag      = struct.unpack('<L', m[0x28:0x2C])[0]
		link_size       = struct.unpack('<L', m[0x2C:0x30])[0]
		link_off        = struct.unpack('<L', m[0x30:0x34])[0]
		map_off         = struct.unpack('<L', m[0x34:0x38])[0]
		string_ids_size = struct.unpack('<L', m[0x38:0x3C])[0]		
		string_ids_off  = struct.unpack('<L', m[0x3C:0x40])[0]
		type_ids_size   = struct.unpack('<L', m[0x40:0x44])[0]
		type_ids_off    = struct.unpack('<L', m[0x44:0x48])[0]
		proto_ids_size  = struct.unpack('<L', m[0x48:0x4C])[0]
		proto_ids_off   = struct.unpack('<L', m[0x4C:0x50])[0]
		field_ids_size  = struct.unpack('<L', m[0x50:0x54])[0]
		field_ids_off   = struct.unpack('<L', m[0x54:0x58])[0]
		method_ids_size = struct.unpack('<L', m[0x58:0x5C])[0]
		method_ids_off  = struct.unpack('<L', m[0x5C:0x60])[0]
		class_defs_size = struct.unpack('<L', m[0x60:0x64])[0]
		class_defs_off  = struct.unpack('<L', m[0x64:0x68])[0]
		data_size       = struct.unpack('<L', m[0x68:0x6C])[0]
		data_off		= struct.unpack('<L', m[0x6C:0x70])[0]

		hdr = {}
		
		hdr['magic'          ] = magic
		hdr['checksum'       ] = checksum
		hdr['sa1'            ] = sa1
		hdr['file_size'      ] = file_size
		hdr['header_size'    ] = header_size
		hdr['endian_tag'     ] = endian_tag
		hdr['link_size'      ] = link_size
		hdr['link_off'       ] = link_off
		hdr['map_off'        ] = map_off
		hdr['string_ids_size'] = string_ids_size
		hdr['string_ids_off' ] = string_ids_off
		hdr['type_ids_size'  ] = type_ids_size
		hdr['type_ids_off'   ] = type_ids_off
		hdr['proto_ids_size' ] = proto_ids_size
		hdr['proto_ids_off'  ] = proto_ids_off
		hdr['field_ids_size' ] = field_ids_size
		hdr['field_ids_off'  ] = field_ids_off
		hdr['method_ids_size'] = method_ids_size
		hdr['method_ids_off' ] = method_ids_off
		hdr['class_defs_size'] = class_defs_size
		hdr['class_defs_off' ] = class_defs_off
		hdr['data_size'      ] = data_size
		hdr['data_off'       ] = data_off
		
		self.header = hdr

	def checksum(self):
		return "%x" %self.header['checksum']

	def string_list(self):
		string_data = []

		string_ids_size = self.header['string_ids_size']
		string_ids_off  = self.header['string_ids_off']

		for i in range(string_ids_size):
			off = struct.unpack('<L', self.mmap[string_ids_off + (i*4) : string_ids_off + (i*4) + 4 ])[0]
			c_size = ord(self.mmap[off])
			c_char = self.mmap[off+1:off+1+c_size]
			string_data.append(c_char)

		self.string_data = string_data #for method_id_list
		return string_data


	def typeid_list(self):
		type_data = []
		type_ids_size = self.header['type_ids_size']
		type_ids_off  = self.header['type_ids_off']

		for i in range(type_ids_size):
			idx = struct.unpack('<L', self.mmap[type_ids_off + (i*4) : type_ids_off + (i*4) + 4])[0]
			type_data.append(idx)

		self.type_data = type_data
		return type_data

	def method_list(self):
		method_data = []

		method_ids_size = self.header['method_ids_size']
		method_ids_off  = self.header['method_ids_off']

		for i in range(method_ids_size):
			class_idx = struct.unpack('<H', self.mmap[method_ids_off+(i*8)  :method_ids_off+(i*8)+2])[0]
			proto_idx = struct.unpack('<H', self.mmap[method_ids_off+(i*8)+2:method_ids_off+(i*8)+4])[0]
			name_idx  = struct.unpack('<L', self.mmap[method_ids_off+(i*8)+4:method_ids_off+(i*8)+8])[0]
			method_data.append([class_idx, proto_idx, name_idx])

		return method_data

	def __del__(self):
		pass