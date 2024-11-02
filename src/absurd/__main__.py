from argparse import ArgumentParser
import sys
from logging import INFO, WARNING, Filter, getLogger, StreamHandler, Formatter, DEBUG
import time
import serial
from .debugger import OcdRev1
from .rspserver import RspServer
from .updi import UpdiRev1, UpdiRev3, UpdiException, WIDTH_BYTE, WIDTH_3BYTE, WIDTH_WORD, KEY_OCD, KEY_NVMPROG
from .deviceinfo import get_deviceinfo

log = getLogger()
handler = StreamHandler(sys.stderr)
handler.setLevel(WARNING)
handler.setFormatter(Formatter("%(asctime)s [%(levelname)s] %(message)s"))
handler.addFilter(Filter("absurd.rspserver.rspserver"))
log.setLevel(DEBUG)
log.addHandler(handler)


def main():
    parser = ArgumentParser(description="AVR Basic SerialUPDI Remote Debugger")
    parser.add_argument("-p", "--part", help="MCU name (e.g. avr16ea48)", required=True)
    parser.add_argument("-P", "--port", help="Serial port used as SerialUPDI (e.g. COM5 or /dev/ttyS1)", required=True)
    parser.add_argument("-b", "--bps", help="Baud rate for communication (defaults to 115200)", type=int, default=115200)
    parser.add_argument("-r", "--rsp-port", help="TCP port number for RSP communcation with gdb", type=int, required=True)
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
        exit(1)
    except UpdiException as ex:
        print(f"UPDI instruction `{ex.instruction}` failed", file=sys.stderr)
        uc.resynchronize()
        uc.disconnect()
        exit(1)
    
    # main loop
    updic = UpdiRev3(args.port, args.bps, updi_prescaler=0)
    try:
        dbg = OcdRev1(updic, flash_offset=devinfo.flash_offset)
        sv = RspServer(args.rsp_port, dbg)
        print("Starting RSP server...")
        sv.serve()
    
    except UpdiException as ex:
        print(f"UPDI instruction `{ex.instruction}` failed", file=sys.stderr)
        updic.disconnect()
        exit(1)
    except StopIteration:
        print(f"Normal termination", file=sys.stderr)
        updic.disconnect()
        exit(0)
    except KeyboardInterrupt:
        print(f"Terminated by Ctrl-C", file=sys.stderr)
        updic.disconnect()
        exit(0)

if __name__=="__main__":
    main()