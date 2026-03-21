from enum import IntEnum, IntFlag
import time
from typing import Optional
from ..updi import WIDTH_BYTE, WIDTH_WORD, UpdiClient, UpdiException, KEY_OCD

OCD = 0x0F80
OCD_BP0A = OCD + 0x00
OCD_BP0AT = OCD + 0x02
OCD_BP1A = OCD + 0x04
OCD_BP1AT = OCD + 0x06
OCD_TRAPEN = OCD + 0x08
OCD_TRAPENL = OCD + 0x08
OCD_TRAPENH = OCD + 0x09
OCD_CAUSE = OCD + 0x0C
OCD_INSN0 = OCD + 0x10
OCD_INSN1 = OCD + 0x12
OCD_PC = OCD + 0x14
OCD_SP = OCD + 0x18
OCD_SREG = OCD + 0x1C
OCD_R0 = OCD + 0x20

# UPDI CSR addresses
UPDI_CTRLA = 0x2
ASI_OCD_CTRLA = 0x4
ASI_OCD_STATUS = 0x5
ASI_RESET_REQ = 0x8
ASI_SYS_STATUS = 0xB
ASI_OCD_MESSAGE = 0xD

# UPDI CSR bitmasks
UPDI_CTRLA_GTVAL_2CYCLES = 0x6
ASI_OCD_STOP = 0x01
ASI_OCD_STOPPED = 0x01
ASI_OCD_RUN = 0x02
ASI_RSTREQ_RESET = 0x59
ASI_RSTREQ_RUN = 0x00
ASI_SYS_SYSRST = 0x20

class Traps(IntFlag):
    INJECT = 0x0001
    HWBP = 0x0002
    STEP = 0x0004
    BP0 = 0x0100
    BP1 = 0x0200
    EXTBRK = 0x1000
    SWBP = 0x2000
    JMP = 0x4000
    INT = 0x8000

class OcdRev1:
    def __init__(self, updi: UpdiClient, flash_offset: int) -> None:
        self.updi = updi
        self.flash_offset = flash_offset
    
    def attach(self):
        try:
            self.updi.connect()
        except UpdiException:
            # UPDI may already be active: try to resynchronize and it's ok if it succeeds
            self.updi.resynchronize()

        self.updi.key(KEY_OCD)
        # Choose minimum guard time since contention is not destructive on an open-drain bus
        self.updi.store_csr(UPDI_CTRLA, UPDI_CTRLA_GTVAL_2CYCLES)
    
    def detach(self):
        self.updi.disconnect()
    
    def halt(self):
        self.updi.store_csr(ASI_OCD_CTRLA, ASI_OCD_STOP)

    def run(self):
        self.updi.store_csr(ASI_OCD_CTRLA, ASI_OCD_RUN)
    
    def is_halted(self):
        return (self.updi.load_csr(ASI_OCD_STATUS) & ASI_OCD_STOPPED) or self.updi.load_direct(OCD_CAUSE) #(self.updi.load_direct(OCD_CAUSE) & 0x04)

    def poll_halted(self, interval: float = 0, count: Optional[int] = None):
        while not self.is_halted():
            if count is not None:
                if count <= 1:
                    return False
                else:
                    count -= 1
            if interval:
                time.sleep(interval)
        return True
    
    def reset(self):
        self.updi.store_csr(ASI_RESET_REQ, ASI_RSTREQ_RESET)
        self.updi.store_csr(ASI_RESET_REQ, ASI_RSTREQ_RUN)
        while self.updi.load_csr(ASI_SYS_STATUS) & ASI_SYS_SYSRST:
            time.sleep(0.01)
        # For better compatibility with older devices
        time.sleep(0.1)

    def set_traps(self, traps: Traps):
        self.updi.store_direct(OCD_TRAPEN, traps, data_width=WIDTH_WORD)

    def enable_traps(self, traps: Traps):
        current = self.updi.load_direct(OCD_TRAPEN, data_width=WIDTH_WORD)
        self.updi.store_direct(OCD_TRAPEN, traps | current, data_width=WIDTH_WORD)

    def disable_traps(self, traps: Traps):
        current = self.updi.load_direct(OCD_TRAPEN, data_width=WIDTH_WORD)
        self.updi.store_direct(OCD_TRAPEN, current & ~traps, data_width=WIDTH_WORD)
    
    def set_bp(self, bpid: int, wordaddr: int):
        byteaddr = (wordaddr << 1) & 0xFFFF
        topbit = wordaddr >> 15
        origregval = self.updi.load_direct(OCD_TRAPENH)
        self.enable_traps(Traps.HWBP)
        if bpid == 0:
            self.updi.store_direct(OCD_BP0A, byteaddr, data_width=WIDTH_WORD)
            self.updi.store_direct(OCD_BP0AT, topbit)
            self.updi.store_direct(OCD_TRAPENH, origregval | 0x1)
        elif bpid == 1:
            self.updi.store_direct(OCD + 0x4, byteaddr, data_width=WIDTH_WORD)
            self.updi.store_direct(OCD + 0x6, topbit)
            self.updi.store_direct(OCD_TRAPENH, origregval | 0x2)

    def clear_bp(self, bpid: int):
        origregval = self.updi.load_direct(OCD_TRAPENH)
        if bpid == 0:
            self.updi.store_direct(OCD_TRAPENH, origregval & ~0x1)
            self.updi.store_direct(OCD_BP0A, 0, data_width=WIDTH_WORD)
            self.updi.store_direct(OCD_BP0AT, 0)
        elif bpid == 1:
            self.updi.store_direct(OCD_TRAPENH, origregval & ~0x2)
            self.updi.store_direct(OCD + 0x4, 0, data_width=WIDTH_WORD)
            self.updi.store_direct(OCD + 0x6, 0)

    def get_pc(self):
        return self.updi.load_direct(OCD_PC, data_width=WIDTH_WORD)-1
    
    def set_pc(self, pc: int):
        # not pc+1; the instruction at the newly set PC is not executed
        # Thus, we have to set PC to pc+1-1...
        self.updi.store_direct(OCD_PC, pc & 0xFFFF, data_width=WIDTH_WORD)
        # ...and do one step to complete that empty cycle, possibly related to instruction fetch
        self.step()

    def get_sp(self):
        return self.updi.load_direct(OCD_SP, data_width=WIDTH_WORD)
    
    def set_sp(self, sp: int):
        self.updi.store_direct(OCD_SP, sp, data_width=WIDTH_WORD)
    
    def get_sreg(self):
        return self.updi.load_direct(OCD_SREG)
    
    def set_sreg(self, sreg: int):
        self.updi.store_direct(OCD_SREG, sreg)
    
    def get_gpr(self, num:int):
        assert 0 <= num < 32
        return self.updi.load_direct(OCD_R0 + num)
    
    def set_gpr(self, num: int, value: int):
        assert 0 <= num < 32
        return self.updi.store_direct(OCD_R0 + num, value)

    def get_register_file(self):
        return self.updi.load_burst(OCD_R0, burst=32)
    
    def set_register_file(self, data:bytes):
        assert len(data)==32
        return self.updi.store_burst(OCD_R0, data, burst=32)

    def step(self):
        origregval = self.updi.load_direct(OCD_TRAPENL)
        self.updi.store_direct(OCD_TRAPENL, origregval | Traps.STEP)
        self.run()
        self.poll_halted()
        self.updi.store_direct(OCD_TRAPENL, origregval)
    
    def read_code(self, start:int, length:int) -> bytes:
        if start < 0 or 0x200000 <= start or length <= 0:
            return bytes()
        length = min(length, 256)
        return self.updi.load_burst(start + self.flash_offset, burst=length)
    
    def read_data(self, start:int, length:int) -> bytes:
        if start < 0 or 0x10000 <= start or length <= 0:
            return bytes()
        length = min(length, 256)
        return self.updi.load_burst(start, burst=length)
    
    def write_data(self, start: int, data: bytes):
        if start < 0 or 0x10000 <= start or len(data) == 0 or len(data) > 256:
            return False
        self.updi.store_burst(start, data, data_width=WIDTH_BYTE, burst=len(data))
        return True

    def execute_instruction(self, instruction: bytes):
        assert len(instruction) in (2, 4)
        self.updi.store_direct(OCD_INSN0, instruction[0] | (instruction[1] << 8), data_width=WIDTH_WORD)
        if len(instruction) == 4:
            self.updi.store_direct(OCD_INSN1, instruction[2] | (instruction[3] << 8), data_width=WIDTH_WORD)
        self.enable_traps(Traps.INJECT)
        self.step()
        self.disable_traps(Traps.INJECT)


    def dump_ocd(self):
        dump = self.updi.load_burst(OCD, burst=64)
        bp0 = dump[0] | (dump[1] << 8) | (dump[2] << 16)
        bp1 = dump[4] | (dump[5] << 8) | (dump[6] << 16)
        trapen = dump[8] | (dump[9] << 8)
        trapstr = (("I" if trapen & Traps.INT else "_")
                   + ("J" if trapen & Traps.JMP else "_")
                   + ("S" if trapen & Traps.SWBP else "_")
                   + ("X" if trapen & Traps.EXTBRK else "_")
                   + ("1" if trapen & Traps.BP1 else "_")
                   + ("0 " if trapen & Traps.BP0 else "_ ")
                   + ("P" if trapen & Traps.STEP else "_")
                   + ("H" if trapen & Traps.HWBP else "_")
                   + ("I" if trapen & Traps.INJECT else "_"))
        cd = dump[12] | (dump[13] << 8)
        pc = dump[0x14] | (dump[0x15] << 8)
        sp = dump[0x18] | (dump[0x19] << 8)
        sreg = dump[0x1c]
        sregstr = (("I" if sreg & 0x80 else "i")
                   + ("T" if sreg & 0x40 else "t")
                   + ("H" if sreg & 0x20 else "h")
                   + ("S" if sreg & 0x10 else "s")
                   + ("V" if sreg & 0x08 else "v")
                   + ("N" if sreg & 0x04 else "n")
                   + ("Z" if sreg & 0x02 else "z")
                   + ("C" if sreg & 0x01 else "c"))
        rf = dump[0x20:0x40].hex(",")
        print(f"BP0:\t 0x{bp0>>1:04x} W (0x{bp0:05x} B)")
        print(f"BP1:\t 0x{bp1>>1:04x} W (0x{bp1:05x} B)")
        print(f"TRAPEN:\t 0x{trapen:04x} ({trapstr})")
        print(f"REASON:\t 0x{cd:04x}")
        print(f"PC:\t 0x{pc-1:04x} W (0x{(pc-1)<<1:05x} B)\nSP:\t 0x{sp:04x}\nSREG:\t {sregstr}")
        print(f"Rn:\t {rf}\n")
