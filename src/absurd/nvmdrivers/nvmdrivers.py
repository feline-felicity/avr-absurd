import time
from abc import ABC, abstractmethod
from ..updi import UpdiClient, DataWidth


class NvmDriver(ABC):
    def __init__(self, updi: UpdiClient, flash_offset: int):
        self.updi = updi
        self.flash_offset = flash_offset

    def _flash_addr(self, code_byteaddr: int) -> int:
        return code_byteaddr + self.flash_offset

    @abstractmethod
    def read_signature(self) -> bytes:
        pass

    @abstractmethod
    def erase_page(self, byteaddr: int):
        pass

    @abstractmethod
    def program_page(self, byteaddr: int, data: bytes):
        pass

    @abstractmethod
    def read_page(self, byteaddr: int) -> tuple[int, bytes]:
        pass


class NvmDriverP0(NvmDriver):
    # More conventional page-oriented flash memories.
    NVM = 0x1000
    CTRLA = NVM + 0x00
    STATUS = NVM + 0x02
    STATUS_BUSY = 0x03  # EEBUSY | FBUSY
    CMD_NOP = 0x00
    CMD_WP = 0x01
    CMD_ER = 0x02
    CMD_PBC = 0x04
    SIGROW = 0x1100

    def __init__(self, updi: UpdiClient, flash_offset: int):
        super().__init__(updi, flash_offset)
        self.page_size = None

    def _poll_idle(self, timeout=1.0):
        start = time.monotonic()
        while self.updi.load_direct(self.STATUS) & self.STATUS_BUSY:
            if time.monotonic() - start > timeout:
                raise TimeoutError("NVM operation timed out")
            time.sleep(0.001)
        self.updi.store_direct(self.CTRLA, self.CMD_NOP)

    def read_signature(self) -> bytes:
        return self.updi.load_burst(self.SIGROW, burst=3, data_width=DataWidth.BYTE)

    def _get_page_size(self):
        if self.page_size is not None:
            return self.page_size
        # On P:0 devices, the page size is 64 bytes for devices with <=16KB flash, and 128 bytes for devices with >16KB flash.
        # So far, the second byte of the signature corresponds to flash size. 0x91=2 KiB, ... , 0x94=16 Kib, 0x95=32 KiB, ... 0x97=128 KiB.
        sig = self.read_signature()
        self.page_size = 64 if sig[1] <= 0x94 else 128
        return self.page_size

    def erase_page(self, byteaddr: int):
        self._poll_idle()
        self.updi.store_direct(self._flash_addr(byteaddr), self.CMD_NOP)
        self.updi.store_direct(self.CTRLA, self.CMD_ER)
        self._poll_idle()

    def program_page(self, byteaddr: int, data: bytes):
        ps = self._get_page_size()
        if len(data) > ps:
            raise ValueError("Data length exceeds page size")
        if byteaddr % ps != 0:
            raise ValueError("Byte address must be aligned to page size")
        self._poll_idle()
        self.updi.store_direct(self.CTRLA, self.CMD_PBC)
        self.updi.store_burst(self._flash_addr(byteaddr), data)
        self.updi.store_direct(self.CTRLA, self.CMD_WP)
        self._poll_idle()

    def read_page(self, byteaddr: int) -> tuple[int, bytes]:
        ps = self._get_page_size()
        aligned_addr = byteaddr - (byteaddr % ps)
        data = self.updi.load_burst(self._flash_addr(aligned_addr), burst=ps)
        return aligned_addr, data


class NvmDriverP3(NvmDriverP0):
    NVM = 0x1000
    CTRLA = NVM + 0x00
    STATUS = NVM + 0x06
    STATUS_BUSY = 0x03  # FLBUSY | EEBUSY
    CMD_NOP = 0x00
    CMD_WP = 0x04  # FLPW
    CMD_ER = 0x08  # FLPER
    CMD_PBC = 0x0F  # FLPBCLR
    SIGROW = 0x1100

    def _get_page_size(self):
        if self.page_size is not None:
            return self.page_size
        # For P:3, somehow the border lies between 32KB and 64KB, i.e. 0x95 and 0x96.
        sig = self.read_signature()
        self.page_size = 64 if sig[1] <= 0x95 else 128
        return self.page_size


class NvmDriverP5(NvmDriverP3):
    # Other than addition of BOOTROW, the NVM controller on P5 is identical to P3.
    # SIGROW is slightly pushed up by BOOTROW.
    SIGROW = 0x1080

    def _get_page_size(self):
        # So far, P:5 devices have the smaller page size.
        return 64


class NvmDriverP2(NvmDriver):
    # Byte-granularity write capable NVM on Dx and derivatives.
    # Page size has been consistently 512 bytes for all byte-granularity NVMs so far.
    NVM = 0x1000
    CTRLA = NVM + 0x00
    STATUS = NVM + 0x02
    STATUS_BUSY = 0x03  # FBUSY | EEBUSY
    CMD_NOP = 0x00
    CMD_FLWR = 0x02
    CMD_FLPER = 0x08
    SIGROW = 0x1100
    PAGE_SIZE = 512

    def __init__(self, updi: UpdiClient, flash_offset: int):
        super().__init__(updi, flash_offset)

    def _poll_idle(self, timeout=1.0):
        start = time.monotonic()
        while self.updi.load_direct(self.STATUS) & self.STATUS_BUSY:
            if time.monotonic() - start > timeout:
                raise TimeoutError("NVM operation timed out")
            time.sleep(0.001)
        self.updi.store_direct(self.CTRLA, self.CMD_NOP)
    
    def read_signature(self) -> bytes:
        return self.updi.load_burst(self.SIGROW, burst=3, data_width=DataWidth.BYTE)

    def erase_page(self, byteaddr: int):
        self._poll_idle()
        self.updi.store_direct(self.CTRLA, self.CMD_FLPER)
        self.updi.store_direct(self._flash_addr(byteaddr), self.CMD_FLPER)
        self._poll_idle()

    def program_page(self, byteaddr: int, data: bytes):
        if len(data) > self.PAGE_SIZE:
            raise ValueError("Data length exceeds page size")
        if byteaddr % self.PAGE_SIZE != 0:
            raise ValueError("Byte address must be aligned to page size")
        self._poll_idle()
        self.updi.store_direct(self.CTRLA, self.CMD_FLWR)
        self.updi.store_burst(self._flash_addr(byteaddr), data[:256])
        if len(data) > 256:
            self.updi.store_burst(self._flash_addr(byteaddr + 256), data[256:])
        self._poll_idle()

    def read_page(self, byteaddr: int) -> tuple[int, bytes]:
        aligned_addr = byteaddr - (byteaddr % self.PAGE_SIZE)
        # Use word burst to cover a 512 byte page. So far, all byte-granularity NVMs have been using 512 byte pages.
        data = self.updi.load_burst(self._flash_addr(aligned_addr), burst=self.PAGE_SIZE // 2, data_width=DataWidth.WORD)
        return aligned_addr, data


class NvmDriverP4(NvmDriverP2):
    # Addition of BOOTROW causes changes in register map and SIGROW position, but as for Flash programming interface, no changes in logic or commands.
    NVM = 0x1000
    CTRLA = NVM + 0x00
    STATUS = NVM + 0x06
    STATUS_BUSY = 0x03  # EEBUSY | FBUSY
    CMD_NOP = 0x00
    CMD_FLWR = 0x02
    CMD_FLPER = 0x08
    SIGROW = 0x1080


class NvmDriverP6(NvmDriverP2):
    # Further changes in register map caused by SECDED ECC and parity, but again no changes in flash programming interface.
    NVM = 0x1000
    CTRLA = NVM + 0x00
    STATUS = NVM + 0x07
    STATUS_BUSY = 0x03  # EEBUSY | FBUSY
    CMD_NOP = 0x00
    CMD_FLWR = 0x02
    CMD_FLPER = 0x08
    SIGROW = 0x1080


def create_nvm_driver(nvm_version: str, updi: UpdiClient, flash_offset: int) -> NvmDriver:
    driver_types = {
        "0": NvmDriverP0,
        "2": NvmDriverP2,
        "3": NvmDriverP3,
        "4": NvmDriverP4,
        "5": NvmDriverP5,
        "6": NvmDriverP6,
    }
    try:
        return driver_types[nvm_version](updi, flash_offset)
    except KeyError as exc:
        raise ValueError(f"Unsupported NVM version: {nvm_version}") from exc
