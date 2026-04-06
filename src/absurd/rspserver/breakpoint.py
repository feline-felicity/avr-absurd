from enum import Enum, auto
from dataclasses import dataclass
from collections import defaultdict
from ..debugger import Ocd
from ..nvmdrivers import NvmDriver
from logging import getLogger
log = getLogger(__name__)


class BreakpointType(Enum):
    INCOMING = auto()
    HARDWARE = auto()
    SOFTWARE = auto()
    OUTGOING_HARDWARE = auto()
    OUTGOING_SOFTWARE = auto()


@dataclass
class Breakpoint:
    byte_address: int
    original_instruction: int  # as a 16-bit word
    type: BreakpointType = BreakpointType.INCOMING
    age: int = 0


BREAK = 0x9598


class BreakpointManager:
    MAX_HWBPS = 2

    def __init__(self, nvmdriver: NvmDriver, debugger: Ocd, allow_swbp: bool = False):
        self.breakpoints: list[Breakpoint] = []
        self.original_image: dict[int, bytes] = {}  # page start byte address -> content of full page
        self.nvmdriver = nvmdriver
        self.debugger = debugger
        self.allow_swbp = allow_swbp
        self.flash_stats: defaultdict[int, int] = defaultdict(int)  # Number of E/W cycles for each page in this session; for logging purposes only

    def _find_bp_by_address(self, byte_address: int) -> Breakpoint | None:
        for bp in self.breakpoints:
            if bp.byte_address == byte_address:
                return bp
        return None

    def _get_original_image(self, page_byte_address: int) -> bytes:
        # return from cache or read from flash and cache
        pageaddr = self.nvmdriver.get_page_base_addr(page_byte_address)
        if pageaddr not in self.original_image:
            log.debug(f"Original page image at {pageaddr:#06x} read from flash")
            self.original_image[pageaddr] = self.nvmdriver.read_page(pageaddr)
        return self.original_image[pageaddr]

    def add_breakpoint(self, byte_address: int):
        # In no-SWBP mode, we reject early if we can't add the breakpoint as a hardware breakpoint, be it new or revived.
        if not self.allow_swbp and sum(1 for bp in self.breakpoints if bp.type in (BreakpointType.INCOMING, BreakpointType.HARDWARE)) >= self.MAX_HWBPS:
            log.debug(f"Rejecting BP registration at {byte_address:#06x} due to slot exhaustion")
            return False

        bp = self._find_bp_by_address(byte_address)
        if bp is not None:
            if bp.type in (BreakpointType.OUTGOING_HARDWARE, BreakpointType.OUTGOING_SOFTWARE):
                log.debug(f"Reviving outgoing BP at {byte_address:#06x}")
                bp.type = BreakpointType.HARDWARE if bp.type == BreakpointType.OUTGOING_HARDWARE else BreakpointType.SOFTWARE
                return True
            log.warning(f"Duplicate BP registration at {byte_address:#06x} rejected")
            return False

        b = self.debugger.read_code(byte_address, 2)
        self.breakpoints.append(Breakpoint(byte_address=byte_address, original_instruction=b[0] | (b[1] << 8), type=BreakpointType.INCOMING))
        log.debug(f"Registered new BP at {byte_address:#06x}")
        return True

    def remove_breakpoint(self, byte_address: int):
        # Mark BP for removal; actual removal happens in commit()
        bp = self._find_bp_by_address(byte_address)
        if bp is None:
            log.warning(f"Attempt to remove non-existent BP at {byte_address:#06x} ignored")
            return
        if bp.type == BreakpointType.HARDWARE:
            log.debug(f"Marked HWBP at {byte_address:#06x} for removal")
            bp.type = BreakpointType.OUTGOING_HARDWARE
        elif bp.type == BreakpointType.SOFTWARE:
            log.debug(f"Marked SWBP at {byte_address:#06x} for removal")
            bp.type = BreakpointType.OUTGOING_SOFTWARE
        elif bp.type == BreakpointType.INCOMING:
            log.debug(f"Removed incoming at {byte_address:#06x} before it was committed")
            self.breakpoints.remove(bp)
        else:
            # No changes otherwise; makes this function idempotent.
            log.warning(f"Duplicate attempt to remove BP at {byte_address:#06x} ignored")

    def commit(self):
        # Clearer logic flow to replace commit()
        updated_pages: dict[int, list[int]] = {}  # { page base address: [offsets of SWBPs in this page]}; all addresses in bytes
        hwbps: list[int] = []
        # 1. Remove outgoing breakpoints, registering empty flash updates for pages that have outgoing SWBPs
        removed_bps = []
        for bp in self.breakpoints:
            if bp.type == BreakpointType.OUTGOING_SOFTWARE:
                page_addr = self.nvmdriver.get_page_base_addr(bp.byte_address)
                if page_addr not in updated_pages:
                    updated_pages[page_addr] = []
                removed_bps.append(bp)
            elif bp.type == BreakpointType.OUTGOING_HARDWARE:
                removed_bps.append(bp)
        for bp in removed_bps:
            self.breakpoints.remove(bp)
        # 2. Sort incoming and hardware breakpoints by type and age; first two candidates become hardware breakpoints
        self.breakpoints.sort(key=lambda bp: (bp.type.value, bp.age))  # Ascending. Incoming, hardware, then software; newer before older.
        for bp in self.breakpoints:
            page_addr = self.nvmdriver.get_page_base_addr(bp.byte_address)
            offset = bp.byte_address - page_addr
            log.debug(f"Active BP: type={bp.type} (age={bp.age}) @ {bp.byte_address:#06x} B (page {page_addr:#06x} + offset {offset:#04x})")
            bp.age += 1
            if bp.type in (BreakpointType.INCOMING, BreakpointType.HARDWARE):
                if len(hwbps) < self.MAX_HWBPS:
                    # First two incoming/hardware BPs become hardware BPs. Younger BPs are likely to be removed quickly, so HWBP is more likely to be effective.
                    hwbps.append(bp.byte_address)
                    bp.type = BreakpointType.HARDWARE
                else:
                    # No more slots. These has to be converted to software BPs.
                    if page_addr not in updated_pages:
                        updated_pages[page_addr] = []
                    updated_pages[page_addr].append(offset)
                    bp.type = BreakpointType.SOFTWARE
            elif bp.type == BreakpointType.SOFTWARE:
                # 3. Re-register existing SWBPs if they are overwritten by changes above
                # Note that this executes after all Incoming and Hardware BPs are processed due to sorting above.
                if page_addr in updated_pages:
                    updated_pages[page_addr].append(offset)
        # add_breakpoint() should have prevented this from happening; sanity check.
        assert self.allow_swbp or not updated_pages
        # 4. Calculate new image for each page in updated_pages, and perform flash updates
        for page_addr, offsets in updated_pages.items():
            new_image = bytearray(self._get_original_image(page_addr))
            for offset in offsets:
                new_image[offset] = BREAK & 0xFF
                new_image[offset + 1] = (BREAK >> 8) & 0xFF
            log.info(f"Updating page at {page_addr:#06x} containing {len(offsets)} SWBP(s)")
            self.flash_stats[page_addr] += 1
            self.nvmdriver.erase_page(page_addr)
            self.nvmdriver.program_page(page_addr, bytes(new_image))
        # 5. Set hardware breakpoints
        self.debugger.clear_bp()
        for idx, bpbyteaddr in enumerate(hwbps):
            wordaddr = bpbyteaddr // 2
            self.debugger.set_bp(idx, wordaddr)
            log.debug(f"Set HWBP{idx} at byte address {bpbyteaddr:#06x} (word address {wordaddr:#04x})")
        # 6. Invalidate pipeline (not sure if this is needed)
        self.debugger.set_pc(self.debugger.get_pc())

    def cleanup(self):
        restored_pages: list[int] = []
        for bp in self.breakpoints:
            if bp.type in (BreakpointType.SOFTWARE, BreakpointType.OUTGOING_SOFTWARE):
                page_addr = self.nvmdriver.get_page_base_addr(bp.byte_address)
                if page_addr not in restored_pages:
                    restored_pages.append(page_addr)
        for page_addr in restored_pages:
            log.info(f"Restoring page at {page_addr:#06x}")
            self.flash_stats[page_addr] += 1
            self.nvmdriver.erase_page(page_addr)
            self.nvmdriver.program_page(page_addr, self._get_original_image(page_addr))
        self.debugger.clear_bp()
        log.debug("Cleared all hardware breakpoints")
        if self.flash_stats:
            print("Flash usage report:")
            for addr in sorted(self.flash_stats.keys()):
                print(f"  Page {addr:#06x} B: {self.flash_stats[addr]} cycles")
            self.flash_stats.clear()

    def get_original_instruction(self, byte_address: int) -> int | None:
        """
        Returns the original instruction at the given byte address if a SWBP is active there, or None otherwise.
        """
        bp = self._find_bp_by_address(byte_address)
        if bp is not None and bp.type in (BreakpointType.SOFTWARE, BreakpointType.OUTGOING_SOFTWARE):
            return bp.original_instruction
        return None
