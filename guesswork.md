# OCD Registers
## What we know for sure

An earlier version of ATtiny817's datasheet had some extra description of now-undocumented OCD-related features, including...  
- OCD activation key `OCD     `
- Three ASI control and status registers:
  - `ASI_OCD_CTRLA` at 0x4
  - `ASI_OCD_STATUS` at 0x5
  - `ASI_OCD_MESSAGE` at 0xD

With these registers, we can halt/resume the CPU, and, if you care, control if the CPU is stopped on reset. Since we can peep and tweak everything with an address by UPDI, this limited set of features might be enough for basic scenarios. However, there are some important features missing, which datasheets state to be present:
- access to register file and Program Counter (PC), which are not memory mapped
- breakpoints
- single-stepping

These features seem to be controlled by the OCD peripheral. Fortunately, its presence and the base address of 0x0F80 is known from the datasheets (this is still documented in EA's). So, why don't we carpet-bomb its vicinity?

## The Guesswork
### FF-bombing OCD registers

With a 128DB48 programmed with a simple firmware, I tried writing 0xFFs to addresses from 0x0F80 by UPDI and examined which bits were actually set. Though only writable bits can be found this way, this turned out to be very effective this time, especially with the first eight bytes.

After the FF-bombardment, values at OCD+0x00 to 0x3 was `[0xFE, 0xFF, 0x01, 0x00]`, that is, bits 1 to 16 of this 4-byte wide field were present and bit 0 and bits above the 16th were not. We all know this pattern. **This is a *byte* address in the code space**. AVR instructions are 2-byte word wide, so there is never an instruction at an odd address, and the LSb of this field need not be present. AVR128DB48 has 128 KiB of flash memory, which is the largest among modern AVRs and requires 17 bits to address a byte.

The following 4-byte field had the same pattern. Since no other field was this (17 bits) wide to contain the code address, these two registers are very likely to be **breakpoint addresses**, which is further supported by the datasheet's statement that there are two of them.

There were other fully-writable bytes at OCD+0x14, +0x15, +0x18, +0x19, +0x1C. In addition, all bytes from OCD+0x20 to 0x3F were fully writable. These values were actually easier recognized without FF-bombardment. By observing the values in these fields while the CPU was halted in the middle of code, **OCD+0x15:0x14 turned out to be PC**, **OCD+0x19:0x18 SP**, and **OCD+0x1C SREG**. Rather obviously, the 32 bytes from **OCD+0x20 to +0x3F were the register file**, from r0 to r31/ZH. Here, the PC is expressed by *word* address, not by byte address like breakpoint registers. In addition, it was later found that this value was actually PC+1.

### Working with bits

Now we know about the wide fields, but the bits in other registers are sparsely implemented, which means they are composed of control bits of different functionalities and each bit has to be separately examined.

There were 8 bits freely modifiable: OCD+0x08[0:2] and OCD+0x09[0:1], [4] and [6:7]. Bit 5 of the latter was constantly set and could not be cleared. Since at least some of these must be the switches to activate breakpoint or other reasons to halt the CPU, I tried setting one of them and run the program until it hit something and halted.

Some bits were easy. **OCD+0x08[2] was single-stepping**. When this bit was set, the core stopped at every instruction. **OCD+0x09[7] corresponded to halt-on-interrupt**, and CPU was stopped on the vector if this bit was set. **OCD+0x09[6] halted the core right after jump/skip instructions**.

Finding enable bits for breakpoints was somewhat harder. After experiments, it was found that **OCD+0x09[0:1] controlled individual breakpoints**, and **OCD+0x08[1] was the global enable bit** for both breakpoints. For a hardware breakpoint to be active, both bits had to be set.

Unfortunately, I could not find what OCD+0x08[0] corresponded to. The constantly-set OCD+0x09[5] seems like to mean software breakpoint is active, which always is.

During these experiments, the read-only registers OCD+0x0C and +0x0D turned out to show what stopped the CPU. In addition to the causes corresponding to the previously described enable bits, there were two other bits: OCD+0x0C[7] for halt-on-reset and [6] for externally issued halt (via ASI_OCD_CTRLA). Somehow OCD+0x0D[0] was shared by BP0 and stepping. OCD+0x0C[2] was always asserted when any of other bits were set.

### OCD.PC and PC
As mentioned above, value at OCD+0x14 (let me call this OCD.PC here) is actually PC+1. When the CPU is halted on reset, OCD.PC gives 0x0001. If the OCD.PC is 0x70, the PC is actually 0x6F, and the instruction at 0x6F is about to be (i.e., not yet) executed.

Additionally, we have to be very careful when modifying the PC. If we move OCD.PC to 0x70 and run, 0x6F is not executed despite the actual PC is at 0x6F. It seems like we have to set PC to actual destination minus one. (Is this related to the pipeline? AVR CPUs take 2 clock cycles to complete a simple instruction: one for instruction fetch and the other for execution.)

### Single-Stepping
~~At first, I thought OCD+0x08[2] caused the CPU to halt on the next instruction. In fact, it turned out that the CPU stopped on the *second* instruction. Initially this didn't make sense at all and troubled me, but the behavior of the PC when it was edited gave me some insights. As described in the previous section, the CPU seems to ignore the instruction PC is on, and the next instruction is the one that is actually executed. So, if we combine modification to PC and this "double-stepping", we can achieve single-stepping. Based on this idea, I implemented single-stepping as `PC=PC-1` plus `OCD+0x08=0x04`. This needs serious testing, but seemingly it's working.~~

~~Now it seems more like a bug of the OCD. Simply setting OCD+0x08[2] works reasonably until the CPU steps on a `sts` instruction. After that, single-stepping becomes double-stepping, and the trick above starts to work. The problem is that if we do the trick from the beginning, the "correct" behavior prevents PC from increasing. To cope with this, we can check if the PC was changed by this operation, and if it did not change, we do the stepping operation once again without setting PC. This seems to work, and there doesn't seem to be any instruction executed twice.~~

~~By the way, during experimenting with this feature, I found that OCD+0x08[0] caused the PC to stay on the current instruction when stepping was performed. Seemingly, it resulted in no operation executed. This may or may not have something to do with the double-stepping....~~

It was finally found that **slow UPDI clock** was the cause of slippery-stepping. The problem had nothing to do with two-word instructions or `sts` instruction. The `sts` instruction I blamed above was actually writing `CLKCTRL_FRQSEL_24M_gc` to `CLKCTRL.OSCHFCTRLA`, which increased the CPU frequency from 4 MHz to 24 MHz. At this speed, UPDI seemed to be unable to keep up with the CPU with its default clock of 4 MHz. With `ASI_CTRLA.UPDICLKSEL` set to `0x0` (32 MHz), single-stepping worked just as expected.
 
### Halt on Change of Flow
OCD+0x09[6] causes the CPU to halt right after a jump, which seems to be the "change of flow" breakpoint feature mentioned in datasheets. This feature works on all kinds of instructions that cause PC to jump:
- `cpse`: compare skip if equal
- `sb[i|r][c|s]`: skip if bit in IO-register/GPR is cleared/set
- `br__`: conditional branch
- `[r|i]?jmp`: relative/indirect/direct jump
- `[r|i]?call`: relative/indirect/direct subroutine call
- `ret`/`reti`: return from subroutine/interrupt

### External Break
OCD+0x09[4] seems to control the "External Break" feature described in the early version of TinyAVR 1-Series datasheet. This is a mechanism to halt all devices in a multi-MCU system. With this bit set, the CPU is halted while the EXTBRK input pin level is high. While which pin it is has never been documented, it turned out to be `PA6` for DB family. It can be on a different pin for other families, and it may be possible to remap it using an undocumented PORTMUX register, as is stated by the datasheet.

## Register Map
### OCD ASI Registers
Use `stcs`/`ldcs` UPDI instructions to access these registers

| Addr | Name            | 7       | 6   | 5   | 4     | 3   | 2   | 1   | 0       | Description     |
| ---- | --------------- | ------- | --- | --- | ----- | --- | --- | --- | ------- | --------------- |
| 0x4  | ASI_OCD_CTRLA   | SOR_DIS |     |     |       |     |     | RUN | STOP    | Halt/resume CPU |
| 0x5  | ASI_OCD_STATUS  |         |     |     | OCDMV |     |     |     | STOPPED | CPU status      |
| 0xD  | ASI_OCD_MESSAGE | MESSAGE | -   | -   | -     | -   | -   | -   | ->      | Avail. if OCDMV |

### OCD Memory-mapped Registers
Use `st(s)`/`ld(s)` UPDI instructions to access these registers. Both byte and word access allowed.  
OCD base address is `0x0F80`. The names are of course not official.

| Offset | Name   | 7     | 6   | 5    | 4      | 3   | 2       | 1    | 0        | Description   |
| ------ | ------ | ----- | --- | ---- | ------ | --- | ------- | ---- | -------- | ------------- |
| 0x00   | BP0A   | BP0AL | =   | =    | =      | =   | =       | =>   | 0        | Breakpoint 0  |
| 0x01   | BP0A   | BP0AH | =   | =    | =      | =   | =       | =    | =>       |               |
| 0x02   | BP0A   |       |     |      |        |     |         |      | BP0AT    | (MSb)         |
| 0x04   | BP1A   | BP1AL | =   | =    | =      | =   | =       | =>   | 0        | Breakpoint 1  |
| 0x05   | BP1A   | BP1AH | =   | =    | =      | =   | =       | =    | =>       |               |
| 0x06   | BP1A   |       |     |      |        |     |         |      | BP1AT    | (MSb)         |
| 0x08   | TRAPEN |       |     |      |        |     | STEP    | HWBP | PCHOLD?  | Trap Enable   |
| 0x09   | TRAPEN | INT   | JMP | SWBP | EXTBRK |     |         | BP1  | BP0      |               |
| 0x0C   | CAUSE  | RESET | EXT |      |        |     | STOPPED |      |          | Halt Cause    |
| 0x0D   | CAUSE  | INT   | JMP | SWBP | EXTBRK |     |         | BP1  | BP0_STEP |               |
| 0x14   | PC     | PCL   | =   | =    | =      | =   | =       | =    | =>       | Program Ctr   |
| 0x15   | PC     | PCH   | =   | =    | =      | =   | =       | =    | =>       | word address  |
| 0x18   | SP     | SPL   | =   | =    | =      | =   | =       | =    | =>       | Stack Ptr     |
| 0x19   | SP     |       | SPH | =    | =      | =   | =       | =    | =>       |               |
| 0x1C   | SREG   | I     | T   | H    | S      | Z   | N       | V    | C        | Status Reg    |
| 0x20   | R0     | R0    | =   | =    | =      | =   | =       | =    | =>       | Register file |
| ...    | ...    | ...   | ... | ...  | ...    | ... | ...     | ...  | ...      | ...           |
| 0x3F   | R31/ZH | R31   | =   | =    | =      | =   | =       | =    | =>       | Register file |