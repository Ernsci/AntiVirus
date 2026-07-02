import struct
import os


SUSPICIOUS_SECTIONS = ['.upx', '.packed', '.themida', '.vmp', '.enigma',
                       '.aspack', '.armaged', '.morph', '.nsp0', '.nsp1',
                       '.nsp2', '.pecompact', '.petite']
SUSPICIOUS_IMPORTS = ['CreateRemoteThread', 'WriteProcessMemory',
                      'VirtualAllocEx', 'SetWindowsHookEx',
                      'OpenProcess', 'NtUnmapViewOfSection',
                      'QueueUserAPC', 'RtlCreateUserThread',
                      'WmiExecQuery', 'MiniDumpWriteDump',
                      'CryptUnprotectData', 'IsDebuggerPresent']


class PEParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.data = None
        self.valid = False
        self.sections = []
        self.imports = []
        self.entry_point = 0
        self.image_base = 0
        self.subsystem = 0
        self._parse()

    def _parse(self):
        try:
            with open(self.filepath, 'rb') as f:
                self.data = f.read()
        except Exception:
            return

        if len(self.data) < 64 or self.data[:2] != b'MZ':
            return

        pe_offset = struct.unpack('<I', self.data[0x3C:0x40])[0]
        if self.data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return

        self.valid = True
        self._parse_headers(pe_offset)
        self._parse_sections(pe_offset)
        self._parse_imports(pe_offset)

    def _parse_headers(self, pe_offset):
        coff = pe_offset + 4
        self.machine = struct.unpack('<H', self.data[coff:coff+2])[0]
        self.section_count = struct.unpack('<H', self.data[coff+2:coff+4])[0]

        opt_hdr_start = coff + 20
        magic = struct.unpack('<H', self.data[opt_hdr_start:opt_hdr_start+2])[0]
        if magic == 0x10b:
            self.entry_point = struct.unpack('<I', self.data[opt_hdr_start+16:opt_hdr_start+20])[0]
            self.image_base = struct.unpack('<I', self.data[opt_hdr_start+28:opt_hdr_start+32])[0]
            self.subsystem = struct.unpack('<H', self.data[opt_hdr_start+68:opt_hdr_start+70])[0]
        elif magic == 0x20b:
            self.entry_point = struct.unpack('<I', self.data[opt_hdr_start+16:opt_hdr_start+20])[0]
            self.image_base = struct.unpack('<Q', self.data[opt_hdr_start+24:opt_hdr_start+32])[0]
            self.subsystem = struct.unpack('<H', self.data[opt_hdr_start+68:opt_hdr_start+70])[0]
        else:
            self.valid = False

    def _parse_sections(self, pe_offset):
        coff = pe_offset + 4
        opt_hdr_start = coff + 20
        magic = struct.unpack('<H', self.data[opt_hdr_start:opt_hdr_start+2])[0]
        section_offset = opt_hdr_start + (0xF0 if magic == 0x10b else 0xF8)

        for i in range(min(self.section_count, 100)):
            off = section_offset + i * 40
            if off + 40 > len(self.data):
                break
            name = self.data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
            vsize = struct.unpack('<I', self.data[off+8:off+12])[0]
            vaddr = struct.unpack('<I', self.data[off+12:off+16])[0]
            rsize = struct.unpack('<I', self.data[off+16:off+20])[0]
            roff = struct.unpack('<I', self.data[off+20:off+24])[0]
            characteristics = struct.unpack('<I', self.data[off+36:off+40])[0]
            self.sections.append({
                'name': name, 'vsize': vsize, 'vaddr': vaddr,
                'rsize': rsize, 'roff': roff, 'characteristics': characteristics
            })

    def _parse_imports(self, pe_offset):
        try:
            import_rva = self._get_data_directory(pe_offset, 1)
            if not import_rva:
                return
            for desc_off in range(import_rva, import_rva + 2000, 20):
                if desc_off + 20 > len(self.data):
                    break
                name_rva = struct.unpack('<I', self.data[desc_off+12:desc_off+16])[0]
                if name_rva == 0:
                    break
                dll_name = self._rva_to_string(name_rva)
                if dll_name:
                    thunk = struct.unpack('<I', self.data[desc_off+16:desc_off+20])[0]
                    for _ in range(500):
                        if thunk == 0:
                            break
                        if thunk & 0x80000000:
                            ordinal = thunk & 0xFFFF
                            self.imports.append(f"{dll_name}.ord{ordinal}")
                        else:
                            imp_name = self._rva_to_string(thunk + 2)
                            if imp_name:
                                self.imports.append(f"{dll_name}.{imp_name}")
                        thunk += 4
        except Exception:
            pass

    def _get_data_directory(self, pe_offset, index):
        coff = pe_offset + 4
        opt_hdr_start = coff + 20
        magic = struct.unpack('<H', self.data[opt_hdr_start:opt_hdr_start+2])[0]
        dir_start = opt_hdr_start + (0x60 if magic == 0x10b else 0x70)
        off = dir_start + index * 8
        if off + 8 > len(self.data):
            return None
        rva = struct.unpack('<I', self.data[off:off+4])[0]
        return rva if rva else None

    def _rva_to_string(self, rva):
        for sec in self.sections:
            if sec['vaddr'] <= rva < sec['vaddr'] + sec['vsize']:
                offset = sec['roff'] + (rva - sec['vaddr'])
                end = self.data.find(b'\x00', offset)
                if end != -1:
                    return self.data[offset:end].decode('ascii', errors='replace')
        return None

    def suspicious_sections(self):
        return [s for s in self.sections if s['name'].lower() in SUSPICIOUS_SECTIONS]

    def suspicious_imports(self):
        return [i for i in self.imports if any(x in i for x in SUSPICIOUS_IMPORTS)]

    def has_anomalous_entry(self):
        if not self.sections:
            return False
        code_sections = [s for s in self.sections if s['characteristics'] & 0x20]
        if not code_sections:
            return False
        for s in code_sections:
            if s['vaddr'] <= self.entry_point < s['vaddr'] + s['vsize']:
                return False
        return True

    def section_entropy_suspicious(self, threshold=7.2):
        from utils.helpers import entropy
        for s in self.sections:
            if s['roff'] and s['rsize']:
                data = self.data[s['roff']:s['roff'] + min(s['rsize'], 4096)]
                if entropy(data) > threshold:
                    return True
        return False
