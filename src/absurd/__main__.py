from argparse import ArgumentParser
import sys
from logging import INFO, Filter, getLogger, StreamHandler, Formatter, DEBUG
import time
import serial
from .debugger import Ocd
from .nvmdrivers import create_nvm_driver
from .rspserver import RspServer
from .updi import AddressWidth, UpdiClient, UpdiException, UpdiFeatures, UpdiRev1, KEY_NVMPROG
from .deviceinfo import get_deviceinfo

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


def main():
    parser = ArgumentParser(description="AVR Basic SerialUPDI Remote Debugger")
    parser.add_argument("-p", "--part", help="MCU name (e.g. avr16ea48)", required=True)
    parser.add_argument("-P", "--port", help="Serial port used as SerialUPDI (e.g. COM5 or /dev/ttyS1)", required=True)
    parser.add_argument("-b", "--bps", help="Baud rate for communication (defaults to 115200)", type=int, default=115200)
    parser.add_argument("-r", "--rsp-port", help="TCP port number for RSP communcation with gdb", type=int, default=3333)
    parser.add_argument("-s", "--swbp", help="Enable software breakpoints (WARNING: incompatible with debuggee's IAP operations)", action="store_true")
    parser.add_argument("-v", "--verbose", help="Print more logs", action="store_true")
    # parser.add_argument("-F", "--enable-flashing", help="Enable features that require modifying NVM contents", action="store_true")
    args = parser.parse_args()
    try:
        devinfo = get_deviceinfo(args.part)
    except ValueError:
        print("Part name not recognized")
        exit(1)
    
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
        signature = uc.load_burst(devinfo.signature_addr, burst=3)
        revid = uc.load_direct(0x0F01)              # SYSCFG.REVID
        
        sig = signature.hex("-").upper()
        rev = f"{chr((revid>>4)+64)}{revid&0x0F}" if revid & 0xF0 else chr(revid + 64)
        nvmver = sib[10]
        ocdver = sib[13]
        sibrev = sib[20:22]

        print(f"UPDI rev.{updiver}")
        print(f"SIB: {sib}")
        print(f"Signature: {sig} (revision {rev})")
        print(f"NVM: v{nvmver} / OCD: v{ocdver}")
        
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
    try:
        nvm_driver = create_nvm_driver(nvmver, updic, devinfo.flash_offset)
        dbg = Ocd(updic, flash_offset=devinfo.flash_offset, use_byte_pc=(ocdver == "0"))
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