# radare2-nios

**Altera Nios** architecture plugin for the [Radare2](https://www.radare.org/n/) reverse engineering toolkit.

Nios is a configurable, pipelined, single-issue RISC soft-core CPU for Altera programmable logic devices that was largely forgotten after the early 2000s. The architecture was quickly superseded by Nios II and later Nios V designs; however, there are very few architectural similarities.

This plugin recycles ancient toolchain code from Cygnus Solutions' GNUPro Tool Suite through [CDK4NIOS](https://cdk4nios.sourceforge.net/) and presents it in a form digestible by modern compilers.
