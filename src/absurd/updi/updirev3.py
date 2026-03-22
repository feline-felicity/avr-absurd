import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Tuple, Literal
from logging import getLogger
log = getLogger(__name__)
import serial

class UpdiException(Exception):
    def __init__(self, instruction:str, *args: object) -> None:
        super().__init__(*args)
        self.instruction = instruction


class UnsupportedUpdiFeatureError(UpdiException):
    pass


class AddressWidth(IntEnum):
    BYTE = 0
    WORD = 1
    THREE_BYTE = 2


class DataWidth(IntEnum):
    BYTE = 0
    WORD = 1


class AddressStep(IntEnum):
    NO_CHANGE = 0
    INCREMENT = 1
    DECREMENT = 3


@dataclass(frozen=True)
class UpdiFeatures:
    supported_address_widths: tuple[AddressWidth, ...] = (AddressWidth.BYTE, AddressWidth.WORD, AddressWidth.THREE_BYTE)
    supports_post_decrement: bool = True


UPDI_REV1_FEATURES = UpdiFeatures(
    supported_address_widths=(AddressWidth.BYTE, AddressWidth.WORD),
    supports_post_decrement=False,
)
UPDI_REV2_FEATURES = UpdiFeatures(
    supported_address_widths=(AddressWidth.BYTE, AddressWidth.WORD, AddressWidth.THREE_BYTE),
    supports_post_decrement=False,
)
UPDI_REV3_FEATURES = UpdiFeatures(
    supported_address_widths=(AddressWidth.BYTE, AddressWidth.WORD, AddressWidth.THREE_BYTE),
    supports_post_decrement=True,
)
UPDI_REV4_FEATURES = UPDI_REV2_FEATURES


class UpdiClient:
    """
    UPDI client parameterized by a capability descriptor.
    """

    def __init__(self, serialport:str, baudrate:int, updi_prescaler=0, features: UpdiFeatures | None = None):
        self.uart = serial.Serial(baudrate=115200, parity=serial.PARITY_EVEN, stopbits=serial.STOPBITS_TWO, timeout=1.0)
        self.uart.port = serialport
        self.uart.dtr = False
        self.baudrate = baudrate
        self.updi_prescaler = updi_prescaler
        self.features = features or UPDI_REV3_FEATURES
        self.default_address_width = max(self.features.supported_address_widths)

    def _resolve_address_width(self, addr: int, addr_width: AddressWidth | None, instruction: str) -> AddressWidth:
        resolved = self.default_address_width if addr_width is None else addr_width
        if resolved not in self.features.supported_address_widths:
            raise UnsupportedUpdiFeatureError(instruction, f"Address width {resolved} is not supported by this UPDI client")
        if not ((resolved == AddressWidth.BYTE and 0 <= addr <= 0xFF)
                or (resolved == AddressWidth.WORD and 0 <= addr <= 0xFFFF)
                or (resolved == AddressWidth.THREE_BYTE and 0 <= addr <= 0xFFFFFF)):
            raise ValueError(f"Address 0x{addr:x} does not fit in width {resolved}")
        return resolved

    def _check_pointer_step(self, addr_step: AddressStep | int, instruction: str) -> AddressStep:
        try:
            resolved = AddressStep(addr_step)
        except ValueError as exc:
            raise ValueError(f"Address step {addr_step!r} is not supported") from exc
        if resolved == AddressStep.DECREMENT and not self.features.supports_post_decrement:
            raise UnsupportedUpdiFeatureError(instruction, "Post-decrement addressing is not supported by this UPDI client")
        return resolved
    
    def connect(self) -> int:
        """
        Assumes control of the serial port and connects to the UPDI on-chip interface.
        DTR will be deasserted and then reasserted to generate an HV pulse on SerialUPDI adapters supporting HV-UPDI.
        """
        # there's no spec for how long HV has to be kept asserted, but 1 ms sounds long enough
        log.debug("Opening serial port")
        self.uart.dtr = False
        try:
            self.uart.open()
        except serial.SerialException:
            log.error(f"Could not open {self.uart.name}")
            raise
        
        log.debug("Emitting HV pulse and handshake")
        time.sleep(0.001)
        self.uart.dtr = True
        time.sleep(0.001)
        self.uart.dtr = False
        # Handshake at fixed baud rate of 115200. Spec says t(Deb0) within 200 ns and 1 us, which is hard to comply; usually much longer pulse works
        # self.uart.send_break(0.000_001)
        self.uart.baudrate = 115200
        self.uart.write(b'\x00')
        self.uart.flush()
        # We have 13 ms before sending Sync char
        time.sleep(0.005)
        
        # Added for compatibility with T412
        # stcs CTRLB, 0x08 (Disable contention check)
        self.store_csr(0x03, 0x08)

        # Set UPDI prescaler and switch to specified speed
        self.store_csr(0x09, self.updi_prescaler & 0x03)
        time.sleep(0.01)
        self.uart.baudrate = self.baudrate
        time.sleep(0.01)

        # Check successful communication by `ldcs STATUSA`
        version = self.load_csr(0x00)
        log.info(f"UPDI version: {version >> 4}")
        return version >> 4
    
    def disconnect(self):
        """
        issues `stcs CTRLB, UPDIDIS` and closes serial port if it is open
        """
        if self.uart.is_open:
            self.store_csr(0x3, 4)
            self.uart.close()

    def resynchronize(self) -> int:
        """
        Resynchronizes UPDI communication by sending Break and clearing any communication error
        returns: error code as given in STATUSB.PESIG
        """
        # 25 ms is long enough to be recognized as Break by slowest specified baud rate 
        log.debug("Transmitting double long break")
        # self.uart.send_break(0.025)
        # On request, CH340 changes baudrate immediately, even during active transmission
        # Because of this, we have to send NUL at a very low baudrate, sleep a while, then restore the original rate to simulate a break
        params = self.uart.get_settings()
        self.uart.baudrate = 300
        self.uart.write(b"\0\0")
        self.uart.flush()
        time.sleep(0.1)
        # ldcs STATUSB at 115200 bps
        log.debug("Clearing PESIG by read access")
        self.uart.baudrate = 115200
        self.uart.reset_input_buffer()
        self.uart.write(b'U\x81')
        self.uart.flush()
        buffer = self.uart.read(3)
        if len(buffer) != 3:
            log.error(f"'ldcs STATUSB' after Break timed out; could not connect to MCU (expected 3 bytes, got '{buffer.hex(' ')}')")
            raise UpdiException("ldcs", "`ldcs STATUSB` following a BREAK character failed")
        log.warning(f"UPDI resynchronized; error code: {buffer[2]:02x}")
        # Set prescaler and resume full baudrate
        self.store_csr(0x09, self.updi_prescaler & 0x03)
        time.sleep(0.001)
        self.uart.baudrate = self.baudrate

        return buffer[2]
    
    def command(self, txdata: bytes, n_expected=0, skip_sync=False) -> Tuple[bool, bytes]:
        """
        Transmit `txdata` and wait for reception of `n_expected` bytes.
        Sync character ('U') is automatically prepended to `txdata` unless `skip_sync` is set
        """
        n_tx = len(txdata) if skip_sync else len(txdata) + 1
        self.uart.reset_input_buffer()
        log.debug(f"Command: {txdata.hex(' ')} -> {n_expected} B")
        if skip_sync:
            self.uart.write(txdata)
        else:
            self.uart.write(b'U' + txdata)
        self.uart.flush()
        
        echo = self.uart.read(n_tx)
        if len(echo) != n_tx:
            log.error(f"Instruction echo not received (expected {n_tx} byte(s), got '{echo.hex(' ')}')")
            return False, b"E"
        
        if n_expected == 0:
            return True, bytes()
        
        buffer = self.uart.read(n_expected)
        if len(buffer) != n_expected:
            log.error(f"Expected response not received (expected {n_expected} byte(s), got '{buffer.hex(' ')}')")
            return False, b"R"
        log.debug(f"Response: {buffer.hex(' ')}")
        return True, buffer
    

    def load_csr(self, addr: int) -> int:
        """
        `ldcs addr` instruction (opcode 0x8_)
        """
        assert 0 <= addr <= 0xF
        succ, val = self.command(bytes((0x80 | addr, )), n_expected=1)
        if not succ:
            raise UpdiException("ldcs")
        return val[0]
    
    
    def store_csr(self, addr: int, value: int):
        """
        `stcs addr, value` instruction (opcode 0xC_)
        """
        assert 0 <= addr <= 0xF
        assert 0 <= value <= 0xFF
        succ, val = self.command(bytes((0xC0 | addr, value)))
        if not succ:
            raise UpdiException("stcs")
        
    
    def read_sib(self) -> bytes:
        """
        `key.sib width` instruction (opcode 0xE_)
        Width fixed to `2` (32 bytes), which is undocumented. In fact, 32 bytes are sent even if width is set to 1.
        """
        succ, val = self.command(bytes((0xE6,)), n_expected=32)
        if not succ:
            raise UpdiException("sib")
        return val 
    
    
    def key(self, key: bytes):
        """
        `key` instruction (opcode 0xE_)  
        The keys are ASCII strings available as consts.
        """
        assert len(key) == 8
        succ, val = self.command(bytes((0xE0,)) + key[::-1])
        if not succ:
            raise UpdiException("key")
        
    
    def repeat(self, count: int):
        """
        `repeat count` instruction. (opcode 0xA0)
        * count can be 8 or 16 bits long, but it is limited to 256. There seems to be no practical reason to use 16-bit count.
        * While datasheet ambiguously states `up to 255 repeats`, 256 repeats (i.e. count=255) seems to be accepted by actual hardware.
        """
        assert 1 <= count <= 256
        succ, val = self.command(bytes((0xA0, count-1)))
        if not succ:
            raise UpdiException("repeat")
        
    def load_direct(self, addr: int, addr_width: AddressWidth | None = None, data_width: DataWidth = DataWidth.BYTE) -> int:
        """
        `lds addr` instruction. (opcode 0x0_)
        addr_width: address width
        data_width: data width
        * prefixing with `repeat` is supported by hardware, but omitted from this library
        """
        resolved_addr_width = self._resolve_address_width(addr, addr_width, "lds")
        if resolved_addr_width == AddressWidth.BYTE:
            succ, val = self.command(bytes((0x00 | data_width, addr)), n_expected=data_width + 1)
        elif resolved_addr_width == AddressWidth.WORD:
            succ, val = self.command(bytes((0x04 | data_width, addr & 0xFF, addr >> 8)), n_expected=data_width + 1)
        else:
            succ, val = self.command(bytes((0x08 | data_width, addr & 0xFF, (addr >> 8) & 0xFF, addr >> 16)), n_expected=data_width + 1)

        if succ and data_width == DataWidth.BYTE:
            return val[0]
        elif succ:
            return (val[1] << 8) | val[0]
        else:
            log.error("lds instruction failed")
            raise UpdiException("lds")

    
    def store_direct(self, addr:int, data:int, addr_width:AddressWidth | None = None, data_width:DataWidth = DataWidth.BYTE) -> None:
        """
        `sts addr, val` instruction. (opcode 0x4_)
        addr_width: address width
        data_width: data width
        * prefixing with `repeat` is supported by hardware, but omitted from this library
        """
        assert (data_width == DataWidth.BYTE and 0 <= data <= 0xFF) or (data_width == DataWidth.WORD and 0 <= data <= 0xFFFF)
        resolved_addr_width = self._resolve_address_width(addr, addr_width, "sts")

        if resolved_addr_width == AddressWidth.BYTE:
            succ, val = self.command(bytes((0x40 | data_width, addr)), n_expected=1)
        elif resolved_addr_width == AddressWidth.WORD:
            succ, val = self.command(bytes((0x44 | data_width, addr & 0xFF, addr >> 8)), n_expected=1)
        else:
            succ, val = self.command(bytes((0x48 | data_width, addr & 0xFF, (addr >> 8) & 0xFF, addr >> 16)), n_expected=1)
        if not succ or val[0] != 0x40:
            log.error(f"sts instruction failed at addressing stage: {val}")
            raise UpdiException("sts", "`sts` instruction did not receive ACK in address stage")

        databytes = bytes((data,)) if data_width == DataWidth.BYTE else bytes((data & 0xFF, data >> 8))
        succ, val = self.command(databytes, n_expected=1, skip_sync=True)
        if not succ or val[0] != 0x40:
            log.error(f"sts instruction failed at data stage: {val}")
            raise UpdiException("sts", "`sts` instruction did not receive ACK in data stage")


    def load_pointer(self, addr_width:AddressWidth | None = None) -> int:
        """
        `ld ptr` instruction (opcode 0x2_)
        reads the pointer for indirect access by `ld`/`st` instructions.
        addr_width: address width
        """
        resolved_addr_width = self.default_address_width if addr_width is None else addr_width
        if resolved_addr_width not in self.features.supported_address_widths:
            raise UnsupportedUpdiFeatureError("ld", f"Address width {resolved_addr_width} is not supported by this UPDI client")
        succ, val = self.command(bytes((0x28 | resolved_addr_width,)), n_expected=resolved_addr_width + 1)
        if not succ:
            raise UpdiException("ld", "`ld ptr`")
        
        if resolved_addr_width == AddressWidth.BYTE:
            return val[0]
        elif resolved_addr_width == AddressWidth.WORD:
            return val[0] | (val[1] << 8)
        else:
            return val[0] | (val[1] << 8) | (val[2] << 16)
        
        
    def store_pointer(self, addr:int, addr_width:AddressWidth | None = None) -> None:
        """
        `st ptr` instruction (opcode 0x6_)
        sets the pointer for indirect access by `ld`/`st` instructions.
        addr_width: address width
        """
        resolved_addr_width = self._resolve_address_width(addr, addr_width, "st")

        if resolved_addr_width == AddressWidth.BYTE:
            succ, val = self.command(bytes((0x68, addr)), n_expected=1)
        elif resolved_addr_width == AddressWidth.WORD:
            succ, val = self.command(bytes((0x69, addr & 0xFF, addr >> 8)), n_expected=1)
        else:
            succ, val = self.command(bytes((0x68 | resolved_addr_width, addr & 0xFF, (addr >> 8) & 0xFF, addr >> 16)), n_expected=1)
        if not succ or val[0]!=0x40:
            log.error(f"st ptr instruction failed: {val}")
            raise UpdiException("st", "`st ptr`")
        
    
    def load_indirect(self, data_width:DataWidth = DataWidth.BYTE, addr_step:AddressStep | int = AddressStep.INCREMENT, burst=1) -> bytes:
        """
        `ld *ptr` instruction (opcode 0x2_)
        loads data at the address pointed by the pointer.
        data_width: (byte or word)
        addr_step: addressing mode (`AddressStep.NO_CHANGE`, `AddressStep.INCREMENT`, `AddressStep.DECREMENT`)
        burst: number of bytes/words stored in burst (must match the operand of preceding `repeat` instruction)
        return: bytes for both `data_width`s (low byte first to match memory layout)
        """
        resolved_addr_step = self._check_pointer_step(addr_step, "ld")
        succ, val = self.command(bytes((0x20 | (resolved_addr_step << 2) | data_width,)), n_expected=burst * (data_width + 1))
        if not succ:
            raise UpdiException("ld", f"`ld` expected {burst} {['byte','word'][data_width]}(s)")
        return val 

    def store_indirect(self, data: bytes, data_width:DataWidth = DataWidth.BYTE, addr_step:AddressStep | int = AddressStep.INCREMENT, burst=1) -> None:
        """
        `st *ptr` instruction (opcode 0x6_)
        stores `data` at the address pointed by the pointer.
        data_width: (byte or word)
        addr_step: addressing mode (`AddressStep.NO_CHANGE`, `AddressStep.INCREMENT`, `AddressStep.DECREMENT`)
        burst: number of bytes/words stored in burst (must match the operand of preceding `repeat` instruction)
        """
        assert len(data) == (burst if data_width == DataWidth.BYTE else 2 * burst)
        assert 1 <= burst <= 0xFF
        resolved_addr_step = self._check_pointer_step(addr_step, "st")
        succ, val = self.command(bytes((0x60 | (resolved_addr_step << 2) | data_width,)))
        if not succ:
            log.error(f"st *ptr instruction failed in instruction stage: {val}")
            raise UpdiException("st", f"`st` did not receive own echo in instruction stage")

        for i in range(burst):
            if data_width == DataWidth.BYTE:
                succ, val = self.command(bytes((data[i],)), n_expected=1, skip_sync=True)
            else:
                succ, val = self.command(bytes((data[2 * i], data[2 * i + 1])), n_expected=1, skip_sync=True)

            if not succ or val[0]!=0x40:
                log.error(f"st *ptr instruction failed in data stage: {val}")
                raise UpdiException("st", f"`st` did not receive enough bytes in data stage")

    def load_burst(self, addr: int, data_width: DataWidth = DataWidth.BYTE, burst=1) -> bytes:
        """
        burst indirect load using successive `st ptr`, `repeat` and `ld *ptr++` instructions.
        """
        self.store_pointer(addr)
        self.repeat(burst)
        return self.load_indirect(data_width=data_width, addr_step=AddressStep.INCREMENT, burst=burst)
    
    def store_burst(self, addr: int, data: bytes, data_width: DataWidth = DataWidth.BYTE) -> None:
        """
        burst indirect store using successive `st ptr`, `repeat` and `st *ptr++` instructions.
        """
        if data_width == DataWidth.BYTE:
            burst = len(data)
        else:
            burst = len(data) // 2
        self.store_pointer(addr)
        self.repeat(burst)
        self.store_indirect(data, data_width=data_width, addr_step=AddressStep.INCREMENT, burst=burst)


class UpdiRev3(UpdiClient):
    """
    Compatibility wrapper for the revision-3 feature set.
    """

    def __init__(self, serialport:str, baudrate:int, updi_prescaler=0):
        super().__init__(serialport, baudrate, updi_prescaler=updi_prescaler, features=UPDI_REV3_FEATURES)
