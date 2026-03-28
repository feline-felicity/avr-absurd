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
        bp = self._find_bp_by_address(byte_address)
        if bp is not None:
            if bp.type in (BreakpointType.OUTGOING_HARDWARE, BreakpointType.OUTGOING_SOFTWARE):
                log.debug(f"Reviving outgoing BP at {byte_address:#06x}")
                bp.type = BreakpointType.HARDWARE if bp.type == BreakpointType.OUTGOING_HARDWARE else BreakpointType.SOFTWARE
                return True
            log.warning(f"Duplicate BP registration at {byte_address:#06x} rejected")
            return False
        # Reject early (on Zn packet) if we can't add the breakpoint; interacts better with gdb.
        # Note this has to be done after confirming this is actually a new breakpoint.
        if not self.allow_swbp and len(self.breakpoints) >= self.MAX_HWBPS:
            log.debug(f"Rejecting BP registration at {byte_address:#06x} due to slot exhaustion")
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

    def _aggregate_updates(self, flash_updates: dict[int, int | None]) -> dict[int, bytearray]:
        page_updates: dict[int, bytearray] = {}
        for addr, new_word in flash_updates.items():
            page_addr = self.nvmdriver.get_page_base_addr(addr)
            if page_addr not in page_updates:
                page_updates[page_addr] = bytearray(self._get_original_image(page_addr))
            offset = addr - page_addr
            if new_word is not None:
                page_updates[page_addr][offset] = new_word & 0xFF
                page_updates[page_addr][offset + 1] = (new_word >> 8) & 0xFF
            # For None (restore original), just leaving the original image (as obtained from _get_original_image()) is sufficient.
        return page_updates

    def commit(self):
        """
        Commit all changes made to breakpoints while the target is halted.
        """
        flash_updates: dict[int, int | None] = {}
        hwbps: list[int] = []
        # 1. Actually remove all outgoing breakpoints; for outgoing software breakpoints, register flash updates to restore the original instruction.
        removed_bps = []
        for bp in self.breakpoints:
            if bp.type == BreakpointType.OUTGOING_SOFTWARE:
                flash_updates[bp.byte_address] = None
                removed_bps.append(bp)
            elif bp.type == BreakpointType.OUTGOING_HARDWARE:
                # Just remove HWBP; no flash update needed.
                removed_bps.append(bp)
        for bp in removed_bps:
            self.breakpoints.remove(bp)

        # 2. Sort incoming and hardware breakpoints by type and age; first two candidates become hardware breakpoints
        self.breakpoints.sort(key=lambda bp: (bp.type.value, bp.age))  # Ascending. Incoming, hardware, then rest; newer before older.
        for bp in self.breakpoints:
            log.debug(f"Active BP: type={bp.type} @ {bp.byte_address:#06x} B (age={bp.age})")
            bp.age += 1
            if bp.type in (BreakpointType.INCOMING, BreakpointType.HARDWARE):
                if len(hwbps) < self.MAX_HWBPS:
                    # First two incoming/hardware BPs become hardware BPs. Younger BPs are likely to be removed quickly, so HWBP is more likely to be effective.
                    hwbps.append(bp.byte_address)
                    bp.type = BreakpointType.HARDWARE
                else:
                    # No more slots. These has to be converted to software BPs.
                    flash_updates[bp.byte_address] = BREAK
                    bp.type = BreakpointType.SOFTWARE
            # Existing SWBPs require no action

        # 3. Perform flash updates, if allowed.
        # By limiting BP number to MAX_HWBPS in add_breakpoint(), we should have enforced this. Extra sanity check just in case.
        assert self.allow_swbp or not flash_updates
        # Make a dictionary of page vs its new content
        page_updates = self._aggregate_updates(flash_updates)
        for page_addr, new_content in page_updates.items():
            log.info(f"Updating page at {page_addr:#06x}")
            self.flash_stats[page_addr] += 1
            self.nvmdriver.erase_page(page_addr)
            self.nvmdriver.program_page(page_addr, bytes(new_content))

        # 4. Set hardware breakpoints
        self.debugger.clear_bp()
        for idx, bpbyteaddr in enumerate(hwbps):
            wordaddr = bpbyteaddr // 2
            self.debugger.set_bp(idx, wordaddr)
            log.debug(f"Set HWBP{idx} at byte address {bpbyteaddr:#06x} (word address {wordaddr:#04x})")

        # 5. Invalidate pipeline (not sure if this is needed)
        self.debugger.set_pc(self.debugger.get_pc())

    def cleanup(self):
        flash_updates: dict[int, int | None] = {}
        for bp in self.breakpoints:
            if bp.type in (BreakpointType.SOFTWARE, BreakpointType.OUTGOING_SOFTWARE):
                flash_updates[bp.byte_address] = None
        page_updates = self._aggregate_updates(flash_updates)
        for page_addr, new_content in page_updates.items():
            log.info(f"Restoring page at {page_addr:#06x}")
            self.flash_stats[page_addr] += 1
            self.nvmdriver.erase_page(page_addr)
            self.nvmdriver.program_page(page_addr, bytes(new_content))
        self.debugger.clear_bp()
        log.debug("Cleared all hardware breakpoints")
        if self.flash_stats:
            log.info("Flash usage report:")
            for addr in sorted(self.flash_stats.keys()):
                log.info(f"  Page {addr:#06x} B: {self.flash_stats[addr]} cycles")
            self.flash_stats.clear()

    def get_original_instruction(self, byte_address: int) -> int | None:
        """
        Returns the original instruction at the given byte address if a SWBP is active there, or None otherwise.
        """
        bp = self._find_bp_by_address(byte_address)
        if bp is not None and bp.type in (BreakpointType.SOFTWARE, BreakpointType.OUTGOING_SOFTWARE):
            return bp.original_instruction
        return None
