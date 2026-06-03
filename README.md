# radare2-nios

**Altera Nios** architecture plugin for the [Radare2](https://www.radare.org/n/) reverse engineering toolkit.

Nios is a configurable, pipelined, single-issue RISC soft-core CPU for Altera programmable logic devices that was largely forgotten after the early 2000s. The architecture was quickly superseded by Nios II and later Nios V designs; however, there are very few architectural similarities.

This plugin recycles ancient toolchain code from Cygnus Solutions' GNUPro Tool Suite through [CDK4NIOS](https://cdk4nios.sourceforge.net/) and presents it in a form digestible by modern compilers.

## Features

- Support for both the 16-bit and 32-bit architecture variants
- A disassembler frontend, wrapping [CGEN](https://sourceware.org/cgen/docs/cgen_1.html) (*Cpu tools GENerator*)
- Basic analysis support for different instruction types and execution flow

## Install via source

To manually build and install to your user plugin directory:

```sh
meson setup builddir -Dplugindir=$(r2 -H R2_USER_PLUGINS)
ninja -C builddir
ninja -C builddir install
```
