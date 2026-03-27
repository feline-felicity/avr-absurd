from ..debugger import Ocd
import sys
import socket
from typing import List
from logging import getLogger
log = getLogger(__name__)

# Signal codes for responses
SIGTRAP = "S05"
SIGINT = "S02"

# Error codes. They're not "well-defined" according to GDB docs. wtf
# These are purely arbitrary
ERR_GENERAL = "E00"
ERR_INVALIDARGS = "E01"
ERR_ADDROUTOFRANGE = "E02"
ERR_READONLY = "E03"
ERR_OUTOFHWBP = "E04"
ERR_NOSUCHBP = "E05"

# TODO: Memory type for the program memory should be "flash" with block size specified
MEMORYMAP = """
<?xml version="1.0"?>
<!DOCTYPE memory-map PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN" "http://sourceware.org/gdb/gdb-memory-map.dtd">
<memory-map>
    <memory type="ram" start="0x800000" length="0x10000"/>
    <memory type="rom" start="0x0" length="0x20000"/>
</memory-map>
""".strip()

def verify_checksum(payload: bytes, checksum: bytes) -> bool:
    try:
        calcdcs = sum(payload) % 256
        recvdcs = int(checksum[:2].decode(encoding="ascii", errors="ignore"), 16)
        return calcdcs == recvdcs
    except ValueError:
        return False


def unescape(data: bytes) -> str:
    parts = data.split(b'}')
    ret = [parts[0].decode("ascii")]
    for run in parts[1:]:
        if len(run) > 0:
            ret.append(chr(run[0] ^ 0x20))
        ret.append(run[1:].decode("ascii"))
    return "".join(ret)


def parse_addr(s: str):
    try:
        addr, length = s.split(",")
        addr = int(addr, 16)
        length = int(length, 16)
        return addr, length
    except ValueError:
        return None, 0


def decode_hex_array(s: str) -> bytes:
    try:
        return bytes(int(s[2 * i:(2 * i + 2)], 16) for i in range(len(s) // 2))
    except ValueError:
        return bytes()


class GdbPacketParser:
    def __init__(self) -> None:
        self.pendingpacket: bytes = bytes()

    def process_bytes(self, data: bytes) -> List[str]:
        if not data:
            return []
        candidates = data.split(b'$')
        candidates[0] = self.pendingpacket + candidates[0]
        # check if the last is compelete separately
        completepackets = [cand.split(b'#', 1) for cand in candidates[:-1] if b'#' in cand[:-2]]
        if b'#' in candidates[-1][:-2]:
            completepackets.append(candidates[-1].split(b'#', 1))
            self.pendingpacket = bytes()
        else:
            self.pendingpacket = candidates[-1]
        # ASCII-safety
        checkedpackets = [(payload, checksum) for (payload, checksum) in completepackets if all(x < 0x80 for x in payload)]
        # Unescape and verify checksum
        unescapedpackets = [up for (payload, checksum) in checkedpackets if verify_checksum((up := unescape(payload)).encode("ascii"), checksum)]
        return unescapedpackets


class RspServer:
    def __init__(self, tcpport: int, debugger: Ocd) -> None:
        sv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sv.bind(("", tcpport))
        sv.listen()
        self.socket = sv
        self.dbg = debugger
        self.packparser = GdbPacketParser()
        self.bps: List[int] = [-1, -1]
    
    def serve(self) -> None:
        log.debug(f"Starting server; attaching to MCU and halting CPU")
        self.dbg.start_session()

        # timeout has to be set for Windows build to accept KeyboardInterrupt
        self.socket.settimeout(0.1)
        client, addr = None, None
        while not client:
            try:
                client, addr = self.socket.accept()
            except socket.timeout:
                pass

        self.client = client
        log.info(f"Accepted connection from {addr}")
        client.setblocking(True)
        client.settimeout(0.1)
        try:
            while True:
                try:
                    data = self.client.recv(1024)
                except socket.timeout:
                    data = bytes()

                packets = self.packparser.process_bytes(data)

                if b'\x03' in data:
                    log.debug(f"Interrupted by GDB, halting CPU and sending SIGINT")
                    client.sendall(b'+')
                    self.dbg.halt_and_wait()
                    self.send_packet(SIGINT)

                for p in packets:
                    client.sendall(b'+')
                    self.handle_packet(p)
                
        finally:
            self.dbg.stop_session()
            client.close()
            self.socket.close()
    
    def handle_packet(self, packet:str):
        log.debug(f"Received Command: {packet}")

        if packet.startswith("qSupported"):
            log.debug(f"Responding to qSupported")
            self.send_packet("PacketSize=1024;qXfer:memory-map:read+")

        elif packet.startswith("qSymbol::"):
            log.debug(f"Responding to qSymbol:: with OK")
            self.send_packet("OK")
            
        elif packet.startswith("!"):
            log.debug(f"Acknowledging extended-remote")
            self.send_packet("OK")

        elif packet.startswith("?"):
            # we're on a baremetal 8-bitter (an excuse for hardcoding SIGTRAP)
            log.debug(f"Responding to ? with SIGTRAP")
            self.send_packet(SIGTRAP)

        elif packet.startswith("s"):
            # TODO: implement "step from..."
            # step should halt the CPU immediately
            log.debug(f"Stepping")
            self.dbg.step()
            self.send_packet(SIGTRAP)

        elif packet.startswith("c"):
            # TODO: implement "continue from..."
            # We have to poll MCU for halted CPU, but we also have to accept interrupt request from GDB, so we poll both alternatingly
            # This would help if PC was moved and pipeline was invalidated(?)
            self.dbg.run()
            log.debug(f"Resumed CPU; now polling for CPU Halt or Client Interrupt")
            while True:
                if self.dbg.is_halted():
                    log.debug(f"CPU halted, sending SIGTRAP")
                    self.send_packet(SIGTRAP)
                    return
                try:
                    b = self.client.recv(1)
                except socket.timeout:
                    b = bytes()
                # We assume we don't receive any packet here
                if b'\x03' in b:
                    log.debug(f"Interrupted by GDB, halting CPU and sending SIGINT")
                    self.client.sendall(b'+')
                    self.dbg.halt_and_wait()
                    self.send_packet(SIGINT)
                    return

        elif packet.startswith("g"):
            # General request for register file
            # 64 chars for GPRs, 2 for SREG, 4 for SP, 8 for byte PC (78 in total)
            log.debug(f"Responding to register file read request (g)")
            gprs = self.dbg.get_register_file().hex()
            sreg = self.dbg.get_sreg()
            sp = self.dbg.get_sp()
            pc = self.dbg.get_pc() << 1
            sph = sp >> 8
            spl = sp & 0xFF
            pct = (pc >> 16) & 0xFF
            pch = (pc >> 8) & 0xFF
            pcl = pc & 0xFF
            response = f"{gprs}{sreg:02x}{spl:02x}{sph:02x}{pcl:02x}{pch:02x}{pct:02x}00"
            log.debug(f"Register File: {response}")
            self.send_packet(response)

        elif packet.startswith("G"):
            # General request for register write
            # 64 chars for GPRs, 2 for SREG, 4 for SP, 8 for byte PC (78 in total)
            log.debug(f"Responding to register file write request (G)")
            data = decode_hex_array(packet[1:])
            if len(data) != 39:
                log.error(f"Invalid operand length")
                self.send_packet(ERR_INVALIDARGS)
                return
            self.dbg.set_register_file(data[:32])
            self.dbg.set_sreg(data[32])
            self.dbg.set_sp(data[33] | (data[34] << 8))
            pc = data[35] | (data[36] << 8) | (data[37] << 16)
            pc >>= 1
            # TODO: we may need to use move_pc if the PC is changed
            self.dbg.set_pc(pc)
            self.send_packet("OK")


        elif packet.startswith("m"):
            # Memory read access. Since modern AVRs map NVMs other than code flash to data space, we only support code (0x0-0x1FFFF) and data (0x800000-0x80FFFF)
            log.debug(f"Responding to memory read request (m)")
            addr, length = parse_addr(packet[1:])
            if addr is None:
                log.error(f"Could not parse command")
                self.send_packet(ERR_INVALIDARGS)
                return
            
            data = None
            if 0 <= addr < 0x200000:
                data = self.dbg.read_code(addr, length)
                log.debug(f"Code at 0x{addr:05x} (0x{addr >> 1:04x} W): {data.hex(' ')}")

            elif 0x800000 <= addr < 0x810000:
                data = self.dbg.read_data(addr - 0x800000, length)
                log.debug(f"Data at 0x{addr - 0x800000:04x}: {data.hex(' ')}")
            
            if data:
                self.send_packet(data.hex())
            else:
                log.error(f"Address out of valid range")
                self.send_packet(ERR_ADDROUTOFRANGE)   

        elif packet.startswith("M"):
            # Memory write access. Only data (0x800000-0x80FFFF) supported.
            log.debug(f"Responding to memory write request (M)")
            cmd = packet[1:].split(":")
            if len(cmd) != 2:
                log.error(f"Could not parse command")
                self.send_packet(ERR_INVALIDARGS)
                return
             
            addr, length = parse_addr(cmd[0])
            data = decode_hex_array(cmd[1])

            if addr is None or len(data) != length:
                log.error(f"Could not parse command")
                self.send_packet(ERR_INVALIDARGS)
                return
            elif not (0x800000 <= addr < 0x810000):
                log.error(f"Address out of valid range")
                self.send_packet(ERR_ADDROUTOFRANGE)

            if self.dbg.write_data(addr-0x800000, data):
                log.debug(f"Data at 0x{addr - 0x800000:04x}: {data.hex(' ')}")
                self.send_packet("OK")
            else:
                log.error(f"Data write failed")
                self.send_packet(ERR_INVALIDARGS)
        # TODO: temporarily fake SWBP
        elif packet.startswith("Z1") or packet.startswith("Z0"):
            # Set hardware BP
            log.debug(f"Responding to HWBP set request (Z1)")
            cmd = packet[3:].split(",")[0]
            try:
                addr = int(cmd, 16)
            except ValueError:
                log.error(f"Could not parse command")
                self.send_packet(ERR_INVALIDARGS)
                return
            
            if self.bps[0] < 0:
                self.bps[0] = addr
                log.debug(f"Setting BP0 to 0x{addr:05x} (0x{addr >> 1:04x} W)")
                self.dbg.set_bp(0, addr >> 1)
                self.send_packet("OK")
            elif self.bps[1] < 0:
                self.bps[1] = addr
                log.debug(f"Setting BP1 to 0x{addr:05x} (0x{addr >> 1:04x} W)")
                self.dbg.set_bp(1, addr >> 1)
                self.send_packet("OK")
            else:
                log.error(f"No free HW BPs")
                self.send_packet(ERR_OUTOFHWBP)

        elif packet.startswith("z1") or packet.startswith("z0"):
            # Clear hardware BP
            log.debug(f"Responding to HWBP clear request (z1)")
            cmd = packet[3:].split(",")[0]
            try:
                addr = int(cmd, 16)
            except ValueError:
                log.error(f"Could not parse command")
                self.send_packet(ERR_INVALIDARGS)
                return
            
            if self.bps[0] == addr:
                self.bps[0] = -1
                log.debug(f"Clearing BP0 at 0x{addr:05x}")
                self.dbg.clear_bp(0)
                self.send_packet("OK")
            elif self.bps[1] == addr:
                self.bps[1] = -1
                log.debug(f"Clearing BP1 at 0x{addr:05x}")
                self.dbg.clear_bp(1)
                self.send_packet("OK")
            else:
                log.error(f"No such HW BPs")
                self.send_packet(ERR_NOSUCHBP)
        
        
        elif packet.startswith("z0") or packet.startswith("Z0"):
            log.debug(f"Responding to SWBP request (z0)")
            self.send_packet(ERR_GENERAL)

        elif packet.startswith("vAttach"):
            log.debug(f"Responding to vAttach with fake SIGTRAP")
            self.send_packet(SIGTRAP)

        elif packet.startswith("qXfer:memory-map:read"):
            log.debug(f"qXfer:memory-map:read::")
            try:
                offset, length = packet[23:].split(",")
                offset = int(offset, 16)
                length = int(length, 16)
            except (ValueError, IndexError):
                log.error(f"Could not parse command")
                self.send_packet(ERR_INVALIDARGS)
                return
            if offset+length >= len(MEMORYMAP):
                self.send_packet("l" + MEMORYMAP[offset:(offset+length)])
            else:
                self.send_packet("m" + MEMORYMAP[offset:(offset+length)])

        elif packet.startswith("qRcmd"):
            # would be a good place to support strange things
            log.debug(f"Monitor Command: {packet}")
            cmd = decode_hex_array(packet[6:]).decode(errors="ignore")
            params = cmd.lower().split()
            if params == ["reset"]:
                log.info(f"Resetting MCU")
                self.dbg.reset()
                self.send_packet("OK")
            elif params == ["inttrap", "on"]:
                log.info(f"Enabling interrupt trap")
                self.dbg.set_break_on_interrupt(True)
                self.send_packet(b'Interrupt trap enabled\n'.hex())
            elif params == ["inttrap", "off"]:
                log.info(f"Disabling interrupt trap")
                self.dbg.set_break_on_interrupt(False)
                self.send_packet(b'Interrupt trap disabled\n'.hex())
            elif params == ["jmptrap", "on"]:
                log.info(f"Enabling jump trap")
                self.dbg.set_break_on_jump(True)
                self.send_packet(b'Jump trap enabled\n'.hex())
            elif params == ["jmptrap", "off"]:
                log.info(f"Disabling jump trap")
                self.dbg.set_break_on_jump(False)
                self.send_packet(b'Jump trap disabled\n'.hex())
            elif params == ["extbrk", "on"]:
                log.info(f"Enabling EXTBRK trap")
                self.dbg.set_external_break(True)
                self.send_packet(b'EXTBRK trap enabled\n'.hex())
            elif params == ["extbrk", "off"]:
                log.info(f"Disabling EXTBRK trap")
                self.dbg.set_external_break(False)
                self.send_packet(b'EXTBRK trap disabled\n'.hex())
            elif params[0] == "exec":
                # expects one or two 16-bit hex numbers.
                if len(params) not in (2, 3):
                    self.send_packet(b'Invalid arguments\n'.hex())
                    return
                try:
                    insns = int(params[1], 16).to_bytes(2, byteorder="little")
                    if len(params) == 3:
                        insns += int(params[2], 16).to_bytes(2, byteorder="little")
                except ValueError:
                    self.send_packet(b'Invalid arguments\n'.hex())
                    return
                log.info(f"Executing instruction(s) {insns.hex(' ')}")
                self.dbg.execute_instruction(insns)
                self.send_packet(b'Instruction executed\n'.hex())
            else:
                log.warning(f"Unrecognized monitor command: {cmd}")
                self.send_packet("")

        elif packet.startswith("k"):
            log.debug(f"Ignoring k command...")

        elif packet.startswith("vKill"):
            log.debug(f"Responding to vKill with fake OK...")
            self.send_packet("OK")
            sys.exit(0)

        elif packet.startswith("vRun"):
            log.debug(f"Resetting MCU upon vRun request")
            self.dbg.reset()
            self.send_packet(SIGTRAP)

        elif packet.startswith("vMustReplyEmpty"):
            log.debug(f"Responding to vMustReplyEmpty with empty packet")
            self.send_packet("")

        elif packet.startswith("vCont?"):
            log.debug(f"Ignoring vCont? for now")
            # TODO: self.send_packet("vCont;s;c;r") after implementing vCont
            self.send_packet("")

        elif packet.startswith("R") or packet.startswith("r"):
            log.debug(f"Resetting MCU upon R/r request")
            self.dbg.reset()  

        elif packet.startswith("T") or packet.startswith("H"):
            log.debug(f"Responding to thread-related command with fake OK...")
            self.send_packet("OK")

        elif packet.startswith("qfThreadInfo"):
            log.debug(f"Responding to qfThreadInfo with fake thread list...")
            self.send_packet("m1")

        elif packet.startswith("qsThreadInfo"):
            log.debug(f"Responding to qsThreadInfo with empty list...")
            self.send_packet("l")

        elif packet.startswith("qC"):
            log.debug(f"Responding to qC with fake thread ID...")
            self.send_packet("QC1")

        elif packet.startswith("qAttached"):
            log.debug(f"Responding to qAttached with 1 (attached)")
            self.send_packet("1")

        elif packet.startswith("D"):
            log.debug(f"Detaching")
            sys.exit(0)

        else:
            log.warning(f"Unknown Command: {packet}")
            self.send_packet("")
    

    def send_packet(self, data: str):
        checksum = f"{sum(data.encode('ascii')) % 256:02x}"
        escaped = data.replace("}", "}\x5d").replace("#","}\x03").replace("$","}\x04").replace("*","}\x0a")
        pack = f"${escaped}#{checksum}".encode("ascii")
        self.client.sendall(pack)

