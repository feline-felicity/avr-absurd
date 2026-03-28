from argparse import ArgumentParser
import sys
from logging import INFO, Filter, getLogger, StreamHandler, Formatter, DEBUG
import time
import serial
from .debugger import Ocd
from .nvmdrivers import create_nvm_driver
from .rspserver import RspServer
from .updi import AddressWidth, UpdiClient, UpdiException, UpdiFeatures, UpdiRev1, KEY_NVMPROG

log = getLogger()
handler = StreamHandler(sys.stderr)
handler.setLevel(INFO)
handler.setFormatter(Formatter("%(asctime)s [%(levelname)s] %(message)s"))
handler.addFilter(Filter("absurd.rspserver.rspserver"))
log.setLevel(DEBUG)
log.addHandler(handler)


def get_updi_features(nvm_version: str) -> UpdiFeatures:
    supported_widths = (AddressWidth.BYTE, AddressWidth.WORD)
    if nvm_version != "0":
        supported_widths += (AddressWidth.THREE_BYTE,)
    return UpdiFeatures(
        supported_address_widths=supported_widths,
        supports_post_decrement=False,
    )


FLASH_SIZE_LUT = {
    0x91: 2 * 1024,
    0x92: 4 * 1024,
    0x93: 8 * 1024,
    0x94: 16 * 1024,
    0x95: 32 * 1024,
    0x96: 64 * 1024,
    0x97: 128 * 1024,
}

MEGA0_SIGS = {
    0x93: (0x26, 0x2A),
    0x94: (0x27, 0x26),
    0x95: (0x30, 0x31),
    0x96: (0x50, 0x51),
}


def get_flash_size(sig: bytes) -> int:
    # With AVR8Xs, flash size can be determined by the middle byte of the signature
    # ...except for 0x96. This denotes 48 KiB for Mega 0 series (SIG3 = 0x50/0x51)
    if sig[1] == 0x96 and sig[2] in MEGA0_SIGS[0x96]:
        return 48 * 1024
    return FLASH_SIZE_LUT.get(sig[1], 0x20000)  # default: 128 KiB, largest possible with 2-byte PC


def get_flash_offset(nvmver: str, sig: bytes) -> int:
    # Except for NVM v0 (Tinies and Mega 0), flash is mapped at 0x800000 in UPDI space.
    if nvmver != "0":
        return 0x800000
    # For NVM v0, we use data space mapping for UPDI access, i.e. 0x8000
    # ...except for Mega 0 again (0x4000).
    if sig[1] in MEGA0_SIGS and sig[2] in MEGA0_SIGS[sig[1]]:
        return 0x4000
    return 0x8000


def main():
    parser = ArgumentParser(description="AVR Basic SerialUPDI Remote Debugger")
    parser.add_argument("-p", "--part", help="MCU name (e.g. avr16ea48)", default="auto") # TODO: currently unused. Cross-examination and manual override to be implemented.
    parser.add_argument("-P", "--port", help="Serial port used as SerialUPDI (e.g. COM5 or /dev/ttyS1)", required=True)
    parser.add_argument("-b", "--bps", help="Baud rate for communication (defaults to 115200)", type=int, default=115200)
    parser.add_argument("-r", "--rsp-port", help="TCP port number for RSP communcation with gdb", type=int, default=3333)
    parser.add_argument("-s", "--swbp", help="Enable software breakpoints (WARNING: incompatible with debuggee's IAP operations)", action="store_true")
    parser.add_argument("-v", "--verbose", help="Print more logs", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        handler.setLevel(DEBUG)

    # As serial port error can happen at any moment, it is never caught by Updi client
    uc = UpdiRev1(args.port, args.bps)
    try:
        # Identify the chip and determine UPDI, NVM & OCD versions
        try:
            updiver: int = uc.connect()
        except UpdiException:
            uc.resynchronize()
            updiver: int = uc.connect()

        time.sleep(0.1)
        sib: str = uc.read_sib().decode(errors="replace")
        uc.key(KEY_NVMPROG)
        uc.store_csr(0x8, 0x59)
        uc.store_csr(0x8, 0x00)
        time.sleep(0.1)

        nvmver = sib[10]
        ocdver = sib[13]
        sibrev = sib[20:22]

        print(f"UPDI rev.{updiver}")
        print(f"SIB: {sib}")
        print(f"NVM: v{nvmver} / OCD: v{ocdver}")

        # Provisional driver for signature reading. Flash offset is irrelevant at this point.
        nvm_driver = create_nvm_driver(nvmver, uc, flash_offset=0x800000)
        signature = nvm_driver.read_signature()
        revid = uc.load_direct(0x0F01)  # SYSCFG.REVID has been consistently here for all AVR8Xs. So far.
        rev = f"{chr((revid >> 4) + 64)}{revid & 0x0F}" if revid & 0xF0 else chr(revid + 64)
        print(f"Signature: {signature.hex("-").upper()} (revision {rev})")
        flash_size = get_flash_size(signature)
        print(f"Flash size: {flash_size // 1024} KiB")
        flash_offset = get_flash_offset(nvmver, signature)
        print(f"UPDI flash offset: {flash_offset:#06x}")

        uc.store_csr(0x8, 0x59)
        uc.store_csr(0x8, 0x00)
        time.sleep(0.1)
        uc.disconnect()

    except serial.SerialException:
        print(f"Error while interacting with serial port `{args.port}`", file=sys.stderr)
        sys.exit(1)
    except UpdiException as ex:
        print(f"UPDI instruction `{ex.instruction}` failed", file=sys.stderr)
        uc.resynchronize()
        uc.disconnect()
        sys.exit(1)
    
    # main loop
    updi_features = get_updi_features(nvmver)
    updic = UpdiClient(args.port, args.bps, updi_prescaler=0, features=updi_features)
    nvm_driver = create_nvm_driver(nvmver, updic, flash_offset)
    try:
        dbg = Ocd(updic, flash_offset=flash_offset, use_byte_pc=(ocdver == "0"))
        sv = RspServer(args.rsp_port, dbg, nvm_driver, allow_swbp=args.swbp)
        log.info(f"Selected NVM driver for SIB NVM version {nvmver}")
        log.info("Starting RSP server...")
        sv.serve()

    except UpdiException as ex:
        log.error(f"UPDI instruction `{ex.instruction}` failed")
        updic.disconnect()
        sys.exit(1)
    except SystemExit:
        log.info(f"Normal termination")
        updic.disconnect()
        raise
    except KeyboardInterrupt:
        log.info(f"Terminated by Ctrl-C")
        updic.disconnect()
        sys.exit(0)

if __name__=="__main__":
    main()