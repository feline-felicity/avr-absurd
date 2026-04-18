# AVR Basic SerialUPDI RSP Debugger
ABSURD is a Python-based GDB remote server that allows GDB to interact with the on-chip debugger (OCD) of modern AVR microcontrollers ("AVR8X") via SerialUPDI.  
ABSURD is licensed under the MIT License.

## Requirements
- SerialUPDI programmer (USB-UART adapter with its TX and RX connected by a Schottky diode to simulate a half-duplex line)
- AVR8X microcontroller with UPDI
  - MegaAVR 0-Series (`ATmega__0_`)
  - TinyAVR 0/1/2-Series (`ATtiny__0_`, `ATtiny__1_`, `ATtiny__2_`)
  - AVR Dx Series (`AVR___DA__[S]`, `AVR___DB__`, `AVR__DD__`, `AVR__DU__`)
  - AVR Ex Series (`AVR__EA__`, `AVR16EB__`)
  - AVR Sx Series (`AVR32SD__`)
  - AVR Lx Series (`AVR__LA__`)
- pySerial Python library

> [!NOTE]
> ABSURD has only been tested with a subset of the devices listed above. Given it is based on guesswork, overgeneralization is quite possible. At the time of writing, no experiments have been performed with SD, and LA remains a header-only device.

### Serial port configuration
Transmission through a serial port may be buffered by OS or device driver. Typically, the buffer is flushed when it is full or after a certain timeout. This can cause significant delay with UPDI communication, which involves back-and-forth exchange of small packets. To mitigate this issue, minimize the buffering timeout in the way specific to OS and UART adapter in use.

Note that a "minimal" timeout like 1 ms is still much longer than a UART character or an AVR clock cycle. This limitation is inherent to the SerialUPDI approach.

## Usage
- Install ABSURD with `pip install absurd`
  - Alternatively, clone this repository and install with `pip install -e .` for development
- Connect MCU to PC with a SerialUPDI programmer
- `avr-absurd -P [serial port name]`
  - or `python -m absurd` instead of `avr-absurd` if it is not in PATH
- Run `avr-gdb` and connect to the server with `target extended-remote :[TCP port number]`
- Optional parameters
  - `-b`/`--bps` baud rate (default: 115200). This can be higher (up to 1.8 MHz) with good SerialUPDI adapters.
  - `-r`/`--rsp-port` TCP port number for RSP (default: 3333)
  - `-s`/`--swbp` enable software breakpoints. Note that use of software breakpoints consumes flash erase/write cycles, and is incompatible with in-application programming
  - `-v`/`--verbose` print more logs

## Features
- Instruction-level stepping
- Two hardware breakpoints
- Optional software breakpoints
  - Wear minimized by use of instruction injection
- Break on...
  - change of flow (after any skip/branch)
  - interrupt
  - external trigger
- Read/write access to register file, RAM and peripheral SFRs
- Flash programming through `load` command
  - Other NVMs (EEPROM/User Row/Boot Row/Fuses) are not supported

### Fixed problems
- OCD v0 (Tiny 0/1) support
- Interrupt handling during stepping
- RSP packet checksum handling

### TODO
- Check auto-detected chip identity/parameters against specified one
  - Chip database to support it
- Chip parameter override

## For developers
- Breaking API change were made to internals
- My guesswork on OCD registers is available [here](./guesswork.md).