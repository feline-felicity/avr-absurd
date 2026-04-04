from ..debugger import Ocd
from .breakpoint import BreakpointManager
from ..nvmdrivers import NvmDriver
import sys
import socket
from typing import List, Literal
from logging import getLogger
log = getLogger(__name__)

# Signal codes for responses
SIGTRAP = "S05"
SIGINT = "S02"

ERR_INVALIDARGS = "E.Invalid parameters"
ERR_ADDROUTOFRANGE = "E.Address out of range"
ERR_OUTOFHWBP = "E.Out of hardware breakpoint slots"


def get_memory_map_xml(page_size: int, flash_size=0x20000) -> str:
    return f"""<?xml version="1.0"?>
<!DOCTYPE memory-map PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN" "http://sourceware.org/gdb/gdb-memory-map.dtd">
<memory-map>
    <memory type="ram" start="0x800000" length="0x10000"/>
    <memory type="flash" start="0x0" length="{flash_size:#x}">
        <property name="blocksize">{page_size:#x}</property>
    </memory>
</memory-map>"""


def parse_addr(b: bytes):
    s = b.decode("ascii", errors="ignore")
    try:
        addr, length = s.split(",")
        addr = int(addr, 16)
        length = int(length, 16)
        return addr, length
    except ValueError:
        return None, 0


def decode_hex_array(s: bytes) -> bytes:
    try:
        return bytes(int(s[2 * i:(2 * i + 2)].decode("ascii"), 16) for i in range(len(s) // 2))
    except (ValueError, UnicodeDecodeError):
        return bytes()


class RspInterface:
    BUFFER_SIZE = 1024 * 16 # Arbitrary empirical limit to handle vFlashWrite

    def __init__(self, tcpport: int):
        sv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sv.bind(("", tcpport))
        sv.listen()
        sv.settimeout(0.1)
        self._socket = sv
        self._packets: List[bytes] = []
        self._expected: Literal["$", "#", "checksum1", "checksum2"] = "$"
        self._escaping = False
        self._buffer = bytearray()
        self._client: socket.socket | None = None
        self._checksum = 0
        self._interrupted = False

    def _process_byte(self, char: int) -> bytes | None:
        if self._client is None:
            raise RuntimeError("No client connected")

        if self._expected == "$":
            if char == ord("$"):
                self._expected = "#"
                self._checksum = 0
                self._buffer.clear()
            elif char == 0x03:
                self._interrupted = True
        elif self._expected == "#":
            if char == ord("}"):
                self._escaping = True
                self._checksum += char
            elif char != ord("#"):
                self._checksum += char
                char = char ^ 0x20 if self._escaping else char
                self._escaping = False
                self._buffer.append(char)
                if len(self._buffer) > self.BUFFER_SIZE:
                    log.warning("Resetting state machine due to buffer overflow")
                    self._expected = "$"
            else:  # char == ord("#")
                self._expected = "checksum1"
        elif self._expected == "checksum1":
            self._buffer.append(char)
            self._expected = "checksum2"
        elif self._expected == "checksum2":
            self._buffer.append(char)
            self._expected = "$"
            payload = bytes(self._buffer[:-2])
            try:
                stated_checksum = int(self._buffer[-2:].decode(encoding="ascii", errors="ignore"), 16)
            except ValueError:
                log.error("Invalid checksum format")
                self._client.sendall(b'-')
                return None
            if self._checksum % 256 == stated_checksum:
                self._client.sendall(b'+')
                return payload
            else:
                log.error(f"Checksum mismatch: {len(payload)} bytes, actual={self._checksum % 256:02x}, stated={stated_checksum:02x}")
                self._client.sendall(b'-')
        return None

    def accept(self):
        while not self._client:
            try:
                self._client, addr = self._socket.accept()
                log.info(f"Accepted connection from {addr}")
            except socket.timeout:
                pass
        self._client.setblocking(True)
        self._client.settimeout(0.1)

    def receive(self, timeout: float | None = None) -> bytes | None:
        if self._client is None:
            raise RuntimeError("No client connected")
        self._client.settimeout(timeout if timeout is not None else 0.1)
        while True:
            if self._packets:
                return self._packets.pop(0)
            try:
                data = self._client.recv(1024)
            except TimeoutError:
                if timeout is None:
                    continue
                else:
                    return None
            for char in data:
                packet = self._process_byte(char)
                if packet is not None:
                    self._packets.append(packet)

    def check_interrupt(self) -> bool:
        if self._client is None:
            raise RuntimeError("No client connected")
        self._client.settimeout(0)
        try:
            data = self._client.recv(1024)
            for char in data:
                packet = self._process_byte(char)
                if packet is not None:
                    self._packets.append(packet)
        except BlockingIOError:
            pass
        if self._interrupted:
            self._interrupted = False
            return True
        return False

    def send(self, data: str):
        if self._client is None:
            raise RuntimeError("No client connected")
        checksum = f"{sum(data.encode('ascii')) % 256:02x}"
        escaped = data.replace("}", "}\x5d").replace("#", "}\x03").replace("$", "}\x04").replace("*", "}\x0a")
        pack = f"${escaped}#{checksum}".encode("ascii")
        self._client.sendall(pack)

    def close(self):
        if self._client:
            self._client.close()
        self._socket.close()


class RspServer:
    def __init__(self, tcpport: int, debugger: Ocd, nvmdriver: NvmDriver, allow_swbp=False) -> None:
        self.dbg = debugger
        self.bps: List[int] = [-1, -1]
        self.tcpport = tcpport
        self.nvmdriver = nvmdriver
        self.allow_swbp = allow_swbp
        self.flash_buffer = bytearray()
        self.flash_buffer_base: int | None = None

    def serve(self) -> None:
        log.debug(f"Starting server; attaching to MCU and halting CPU")
        self.dbg.start_session()

        rspitf = RspInterface(self.tcpport)
        rspitf.accept()

        bpman = BreakpointManager(self.nvmdriver, self.dbg, allow_swbp=self.allow_swbp)

        try:
            while True:
                packet = rspitf.receive()
                self._handle_packet(packet, rspitf, bpman)  # type: ignore (receive() never returns None in non-timeout mode)
        finally:
            bpman.cleanup()
            self.dbg.stop_session()
            rspitf.close()

    def _handle_packet(self, packet: bytes, rspitf: RspInterface, bpman: BreakpointManager) -> None:
        log.debug(f"Received Command: {packet.decode('ascii', errors='replace')}")

        if packet.startswith(b"qSupported"):
            log.debug(f"Responding to qSupported")
            rspitf.send("PacketSize=1024;qXfer:memory-map:read+")

        elif packet.startswith(b"qSymbol::"):
            log.debug(f"Responding to qSymbol:: with OK")
            rspitf.send("OK")

        elif packet.startswith(b"!"):
            log.debug(f"Acknowledging extended-remote")
            rspitf.send("OK")

        elif packet.startswith(b"?"):
            # we're on a baremetal 8-bitter (an excuse for hardcoding SIGTRAP)
            log.debug(f"Responding to ? with SIGTRAP")
            rspitf.send(SIGTRAP)

        elif packet.startswith(b"s"):
            # TODO: implement "step from..."
            # No need to commit breakpoints, but we have to inject the original instruction if we're on a SWBP
            originsn = bpman.get_original_instruction(self.dbg.get_pc() << 1)
            if originsn is not None:
                log.debug(f"Stepping with active SWBP; injecting original instruction {originsn:04x}")
                self.dbg.execute_instruction(originsn.to_bytes(2, byteorder="little"))
            else:
                log.debug(f"Stepping normally")
                self.dbg.step()
            if rspitf.check_interrupt():
                log.debug(f"Interrupted by GDB during step, reply with SIGINT")
                rspitf.send(SIGINT)
            else:
                rspitf.send(SIGTRAP)

        elif packet.startswith(b"c"):
            # TODO: implement "continue from..."
            # Commit breakpoints before resuming CPU
            bpman.commit()
            # We have to poll MCU for halted CPU, but we also have to accept interrupt request from GDB, so we poll both alternatingly
            self.dbg.run()
            log.debug(f"Resumed CPU; now polling for CPU Halt or Client Interrupt")
            while True:
                if self.dbg.is_halted():
                    log.debug(f"CPU halted, sending SIGTRAP")
                    rspitf.send(SIGTRAP)
                    return
                if rspitf.check_interrupt():
                    log.debug(f"Interrupted by GDB, halting CPU and sending SIGINT")
                    self.dbg.halt_and_wait()
                    rspitf.send(SIGINT)
                    return

        elif packet.startswith(b"g"):
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
            rspitf.send(response)

        elif packet.startswith(b"G"):
            # General request for register write
            # 64 chars for GPRs, 2 for SREG, 4 for SP, 8 for byte PC (78 in total)
            log.debug(f"Responding to register file write request (G)")
            data = decode_hex_array(packet[1:])
            if len(data) != 39:
                log.error(f"Invalid operand length")
                rspitf.send(ERR_INVALIDARGS)
                return
            self.dbg.set_register_file(data[:32])
            self.dbg.set_sreg(data[32])
            self.dbg.set_sp(data[33] | (data[34] << 8))
            pc = data[35] | (data[36] << 8) | (data[37] << 16)
            pc >>= 1
            # TODO: we may need to use move_pc if the PC is changed
            self.dbg.set_pc(pc)
            rspitf.send("OK")

        elif packet.startswith(b"m"):
            # Memory read access. Since modern AVRs map NVMs other than code flash to data space, we only support code (0x0-0x1FFFF) and data (0x800000-0x80FFFF)
            log.debug(f"Responding to memory read request (m)")
            addr, length = parse_addr(packet[1:])
            if addr is None:
                log.error(f"Could not parse command")
                rspitf.send(ERR_INVALIDARGS)
                return

            data = None
            if 0 <= addr < 0x200000:
                data = self.dbg.read_code(addr, length)
                log.debug(f"Code at 0x{addr:05x} (0x{addr >> 1:04x} W): {data.hex(' ')}")

            elif 0x800000 <= addr < 0x810000:
                data = self.dbg.read_data(addr - 0x800000, length)
                log.debug(f"Data at 0x{addr - 0x800000:04x}: {data.hex(' ')}")

            if data:
                rspitf.send(data.hex())
            else:
                log.error(f"Address out of valid range")
                rspitf.send(ERR_ADDROUTOFRANGE)

        elif packet.startswith(b"M"):
            # Memory write access. Only data (0x800000-0x80FFFF) supported.
            log.debug(f"Responding to memory write request (M)")
            cmd = packet[1:].split(b":")
            if len(cmd) != 2:
                log.error(f"Could not parse command")
                rspitf.send(ERR_INVALIDARGS)
                return

            addr, length = parse_addr(cmd[0])
            data = decode_hex_array(cmd[1])

            if addr is None or len(data) != length:
                log.error(f"Could not parse command")
                rspitf.send(ERR_INVALIDARGS)
                return
            elif not (0x800000 <= addr < 0x810000):
                log.error(f"Address out of valid range")
                rspitf.send(ERR_ADDROUTOFRANGE)

            if self.dbg.write_data(addr - 0x800000, data):
                log.debug(f"Data at 0x{addr - 0x800000:04x}: {data.hex(' ')}")
                rspitf.send("OK")
            else:
                log.error(f"Data write failed")
                rspitf.send(ERR_INVALIDARGS)

        elif packet.startswith(b"Z1") or packet.startswith(b"Z0"):
            # GDB can't choose between HW and SW breakpoints in a useful way, so we won't distinguish them and use our own logic to assign them.
            cmd = packet[3:].decode("ascii", errors="ignore").split(",")[0]
            try:
                addr = int(cmd, 16)
            except ValueError:
                log.error(f"Could not parse command")
                rspitf.send(ERR_INVALIDARGS)
                return
            
            r = bpman.add_breakpoint(addr)
            if r:
                log.debug(f"Registered BP at 0x{addr:05x} (0x{addr >> 1:04x} W)")
                rspitf.send("OK")
            else:
                log.error(f"Failed to register BP at 0x{addr:05x}")
                rspitf.send(ERR_OUTOFHWBP)

        elif packet.startswith(b"z1") or packet.startswith(b"z0"):
            # Clear hardware BP
            cmd = packet[3:].decode("ascii", errors="ignore").split(",")[0]
            try:
                addr = int(cmd, 16)
            except ValueError:
                log.error(f"Could not parse command")
                rspitf.send(ERR_INVALIDARGS)
                return
            bpman.remove_breakpoint(addr)
            log.debug(f"Deregistered BP at 0x{addr:05x} (0x{addr >> 1:04x} W)")
            rspitf.send("OK")

        elif packet.startswith(b"vAttach"):
            log.debug(f"Responding to vAttach with fake SIGTRAP")
            rspitf.send(SIGTRAP)

        elif packet.startswith(b"qXfer:memory-map:read"):
            log.debug(f"qXfer:memory-map:read::")
            try:
                offset, length = packet[23:].decode("ascii", errors="ignore").split(",")
                offset = int(offset, 16)
                length = int(length, 16)
            except (ValueError, IndexError):
                log.error(f"Could not parse command")
                rspitf.send(ERR_INVALIDARGS)
                return
            mapxml = get_memory_map_xml(self.nvmdriver.get_page_size())
            if offset + length >= len(mapxml):
                rspitf.send("l" + mapxml[offset:(offset + length)])
            else:
                rspitf.send("m" + mapxml[offset:(offset + length)])

        elif packet.startswith(b"qRcmd"):
            # would be a good place to support strange things
            log.debug(f"Monitor Command: {packet}")
            cmd = decode_hex_array(packet[6:]).decode(errors="ignore")
            params = cmd.lower().split()
            if params == ["reset"]:
                log.info(f"Resetting MCU")
                self.dbg.reset()
                rspitf.send("OK")
            elif params == ["inttrap", "on"]:
                log.info(f"Enabling interrupt trap")
                self.dbg.set_break_on_interrupt(True)
                rspitf.send(b'Interrupt trap enabled\n'.hex())
            elif params == ["inttrap", "off"]:
                log.info(f"Disabling interrupt trap")
                self.dbg.set_break_on_interrupt(False)
                rspitf.send(b'Interrupt trap disabled\n'.hex())
            elif params == ["jmptrap", "on"]:
                log.info(f"Enabling jump trap")
                self.dbg.set_break_on_jump(True)
                rspitf.send(b'Jump trap enabled\n'.hex())
            elif params == ["jmptrap", "off"]:
                log.info(f"Disabling jump trap")
                self.dbg.set_break_on_jump(False)
                rspitf.send(b'Jump trap disabled\n'.hex())
            elif params == ["extbrk", "on"]:
                log.info(f"Enabling EXTBRK trap")
                self.dbg.set_external_break(True)
                rspitf.send(b'EXTBRK trap enabled\n'.hex())
            elif params == ["extbrk", "off"]:
                log.info(f"Disabling EXTBRK trap")
                self.dbg.set_external_break(False)
                rspitf.send(b'EXTBRK trap disabled\n'.hex())
            elif params[0] == "exec":
                # expects one or two 16-bit hex numbers.
                if len(params) not in (2, 3):
                    rspitf.send(b'Invalid arguments\n'.hex())
                    return
                try:
                    insns = int(params[1], 16).to_bytes(2, byteorder="little")
                    if len(params) == 3:
                        insns += int(params[2], 16).to_bytes(2, byteorder="little")
                except ValueError:
                    rspitf.send(b'Invalid arguments\n'.hex())
                    return
                log.info(f"Executing instruction(s) {insns.hex(' ')}")
                self.dbg.execute_instruction(insns)
                rspitf.send(b'Instruction executed\n'.hex())
            else:
                log.warning(f"Unrecognized monitor command: {cmd}")
                rspitf.send("")

        elif packet.startswith(b"k"):
            log.debug(f"Ignoring k command...")

        elif packet.startswith(b"vKill"):
            log.debug(f"Responding to vKill with fake OK...")
            rspitf.send("OK")
            sys.exit(0)

        elif packet.startswith(b"vRun"):
            log.debug(f"Resetting MCU upon vRun request")
            self.dbg.reset()
            rspitf.send(SIGTRAP)

        elif packet.startswith(b"vMustReplyEmpty"):
            log.debug(f"Responding to vMustReplyEmpty with empty packet")
            rspitf.send("")

        elif packet.startswith(b"vCont?"):
            log.debug(f"Ignoring vCont? for now")
            # TODO: rspitf.send("vCont;s;c;r") after implementing vCont
            rspitf.send("")

        elif packet.startswith(b"R") or packet.startswith(b"r"):
            log.debug(f"Resetting MCU upon R/r request")
            self.dbg.reset()

        elif packet.startswith(b"T") or packet.startswith(b"H"):
            log.debug(f"Responding to thread-related command with fake OK...")
            rspitf.send("OK")

        elif packet.startswith(b"qfThreadInfo"):
            log.debug(f"Responding to qfThreadInfo with fake thread list...")
            rspitf.send("m1")

        elif packet.startswith(b"qsThreadInfo"):
            log.debug(f"Responding to qsThreadInfo with empty list...")
            rspitf.send("l")
        
        elif packet.startswith(b"qThreadExtraInfo"):
            log.debug(f"Responding to qThreadExtraInfo with fake thread name...")
            rspitf.send(b"No thread support".hex())

        elif packet.startswith(b"qC"):
            log.debug(f"Responding to qC with fake thread ID...")
            rspitf.send("QC1")

        elif packet.startswith(b"qAttached"):
            log.debug(f"Responding to qAttached with 1 (attached)")
            rspitf.send("1")

        elif packet.startswith(b"D"):
            log.debug(f"Detaching")
            sys.exit(0)

        elif packet.startswith(b"vFlashErase"):
            addr, length = parse_addr(packet[12:])
            if addr is None:
                log.error("Could not parse address and length in vFlashErase command")
                rspitf.send(ERR_INVALIDARGS)
                return
            self._do_erase_flash(addr, length, rspitf)

        elif packet.startswith(b"vFlashWrite"):
            cmd = packet[12:].split(b":", maxsplit=1)
            if len(cmd) != 2:
                log.error("Could not parse vFlashWrite packet")
                rspitf.send(ERR_INVALIDARGS)
                return
            try:
                addr = int(cmd[0].decode("ascii", errors="ignore"), 16)
            except ValueError:
                log.error("Could not parse address in vFlashWrite command")
                rspitf.send(ERR_INVALIDARGS)
                return
            self._do_write_flash(addr, cmd[1], rspitf)

        elif packet.startswith(b"vFlashDone"):
            self._do_commit_flash_writes(rspitf)

        else:
            log.warning(f"Unknown Command: {packet}")
            rspitf.send("")

    def _do_erase_flash(self, addr: int, length: int, rspitf: RspInterface):
        log.debug(f"Erasing flash from 0x{addr:05x} to 0x{addr + length:05x} ({length} bytes)")
        self.flash_buffer_base = None
        ps = self.nvmdriver.get_page_size()
        if addr < 0 or 0x20000 < addr + length:
            log.error(f"Address out of range (128 KiB)")
            rspitf.send(ERR_ADDROUTOFRANGE)
            return
        if addr % ps != 0 or length % ps != 0:
            log.error(f"Unaligned erase request (page size: {ps} bytes)")
            rspitf.send(ERR_INVALIDARGS)
            return
        for page_addr in range(addr, addr + length, ps):
            log.debug(f"Request to erase page {page_addr // ps} at 0x{page_addr:05x} ignored")
        rspitf.send("OK")

    def _do_write_flash(self, addr: int, data: bytes, rspitf: RspInterface):
        # GDB does NOT give aligned addresses; we'll buffer till vFlashDone for simplicity.
        log.debug(f"Buffering flash write to 0x{addr:05x}, {len(data)} bytes")
        ps = self.nvmdriver.get_page_size()
        if addr < 0 or 0x20000 <= addr + len(data):
            log.error(f"Address out of range (128 KiB)")
            rspitf.send(ERR_ADDROUTOFRANGE)
            return
        if self.flash_buffer_base is None:
            # First write; register base and check for alignment
            if addr % ps != 0:
                log.error(f"Unaligned write request (page size: {ps} bytes)")
                rspitf.send(ERR_INVALIDARGS)
                return
            self.flash_buffer_base = addr
            self.flash_buffer.clear()
        else:
            # Check for contiguity with previous writes
            expected_addr = self.flash_buffer_base + len(self.flash_buffer)
            if addr != expected_addr:
                log.error(f"Non-contiguous write request (expected address: 0x{expected_addr:05x})")
                rspitf.send(ERR_INVALIDARGS)
                return
        # Buffer and return
        self.flash_buffer.extend(data)
        rspitf.send("OK")

    def _do_commit_flash_writes(self, rspitf: RspInterface):
        if self.flash_buffer_base is None:
            log.error(f"vFlashDone received without any buffered data")
            rspitf.send(ERR_INVALIDARGS)
            return
        ps = self.nvmdriver.get_page_size()
        # At this point, nothing has been done to the flash yet. Pre-verify each page to avoid unnecessary writes.
        for page_addr in range(self.flash_buffer_base, self.flash_buffer_base + len(self.flash_buffer), ps):
            pagedata = self.flash_buffer[page_addr - self.flash_buffer_base:page_addr - self.flash_buffer_base + ps]
            currentdata = self.nvmdriver.read_page(page_addr)
            if pagedata == currentdata[:len(pagedata)]:
                log.info(f"Programming page {page_addr // ps} at 0x{page_addr:05x} ({len(pagedata)} bytes) skipped")
            else:
                log.info(f"Programming page {page_addr // ps} at 0x{page_addr:05x} ({len(pagedata)} bytes)")
                self.nvmdriver.erase_page(page_addr)
                self.nvmdriver.program_page(page_addr, pagedata)
        self.flash_buffer.clear()
        self.flash_buffer_base = None
        rspitf.send("OK")
