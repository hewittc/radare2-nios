/* nios plugin by hewittc at 2018-2026 */

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_arch.h>

#include "dis-asm.h"

#include "gnu/nios-desc.h"
#include "gnu/nios-opc.h"

extern void cgen_set_parse_operand_fn(CGEN_CPU_DESC, cgen_parse_operand_fn *);

struct nios_info {
	CGEN_CPU_DESC cgen_cpu;
	CGEN_FIELDS cgen_fields;
};

static struct nios_info *nios;

static const char *nios_parse_operand(CGEN_CPU_DESC cd, enum cgen_parse_operand_type type, const char **strp, int opindex, int opinfo, enum cgen_parse_operand_result *resultp, bfd_vma *valuep) {
	if (type == CGEN_PARSE_OPERAND_INIT) {
		return NULL;
	}

	if (type == CGEN_PARSE_OPERAND_INTEGER || type == CGEN_PARSE_OPERAND_ADDRESS) {
		// Try to parse as register name first
		const char *s = *strp;
		if (isalpha ((unsigned char)s[0]) || s[0] == '_') {
			while (isalnum ((unsigned char)*s) || *s == '_') {
				s++;
			}

			if (s != *strp) {
				char regname[32];
				snprintf (regname, sizeof (regname), "%.*s", (int) (s - *strp), *strp);

				const CGEN_KEYWORD_ENTRY *ke = cgen_keyword_lookup_name (&nios_cgen_opval_gr_names, regname);
				if (ke) {
					*valuep = ke->value;
					*strp = s;
					if (resultp) {
						*resultp = CGEN_PARSE_OPERAND_RESULT_REGISTER;
					}
					return NULL;
				}

				ke = cgen_keyword_lookup_name (&nios_cgen_opval_ctl_names, regname);
				if (ke) {
					*valuep = ke->value;
					*strp = s;
					if (resultp) {
						*resultp = CGEN_PARSE_OPERAND_RESULT_REGISTER;
					}
					return NULL;
				}
			}
		}

		// Parse as number
		char *end;
		long val = strtol (*strp, &end, 0);
		if (end == *strp) {
			return "invalid number";
		}
		*strp = end;
		*valuep = val;
		if (resultp) {
			*resultp = CGEN_PARSE_OPERAND_RESULT_NUMBER;
		}
		return NULL;
	}

	if (type == CGEN_PARSE_OPERAND_SYMBOLIC) {
		*valuep = 0;
		if (resultp) {
			*resultp = CGEN_PARSE_OPERAND_RESULT_QUEUED;
		}
		return NULL;
	}

	return "unsupported parse type";
}

static char *regs(RArchSession *as) {
	int bits = as->config? as->config->bits: 32;
	int step = bits == 16? 2: 4;
	RStrBuf *sb = r_strbuf_new ("");

	// Register aliases
	r_strbuf_appendf (sb, "=SR  ctl0\n");
	r_strbuf_appendf (sb, "=PC  pc\n");
	r_strbuf_appendf (sb, "=SP  o6\n");
	r_strbuf_appendf (sb, "=LR  o7\n");
	r_strbuf_appendf (sb, "=BP  i6\n");
	r_strbuf_appendf (sb, "=SN  g0\n"); // Silence warning, syscalls use TRAP
	r_strbuf_appendf (sb, "=A0  i0\n");
	r_strbuf_appendf (sb, "=A1  i1\n");
	r_strbuf_appendf (sb, "=A2  i2\n");
	r_strbuf_appendf (sb, "=A3  i3\n");
	r_strbuf_appendf (sb, "=A4  i4\n");
	r_strbuf_appendf (sb, "=A5  i5\n");
	r_strbuf_appendf (sb, "=R0  i7\n");

	// Control registers: %ctl0-%ctl9
	for (int i = 0; i < 10; i++) {
		r_strbuf_appendf (sb, "gpr  ctl%d  .%d  %d  0\n", i, bits, i * step);
	}

	// Program counter
	r_strbuf_appendf (sb, "gpr  pc  .%d  %d  0\n", bits, 10 * step);

	// K register
	r_strbuf_appendf (sb, "gpr  k  .16  %d  0\n", 11 * step);

	// Global registers: %r0-%r7 (%g0-%g7)
	for (int i = 0; i < 8; i++) {
		r_strbuf_appendf (sb, "gpr  g%d  .%d  %d  0\n", i, bits, (12 + i) * step);
	}

	// Output registers: %r8-%r15 (%o0-%o7)
	for (int i = 0; i < 8; i++) {
		r_strbuf_appendf (sb, "gpr  o%d  .%d  %d  0\n", i, bits, (20 + i) * step);
	}

	// Local registers: %r16-%r23 (%l0-%l7)
	for (int i = 0; i < 8; i++) {
		r_strbuf_appendf (sb, "gpr  l%d  .%d  %d  0\n", i, bits, (28 + i) * step);
	}

	// Input registers: %r24-%r31 (%i0-%i7)
	for (int i = 0; i < 8; i++) {
		r_strbuf_appendf (sb, "gpr  i%d  .%d  %d  0\n", i, bits, (36 + i) * step);
	}

	return r_strbuf_drain (sb);
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_MINOP_SIZE:
		return 2;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 2;
	case R_ARCH_INFO_INVOP_SIZE:
		return 2;
	case R_ARCH_INFO_CODE_ALIGN:
		return 2;
	case R_ARCH_INFO_DATA_ALIGN:
		return 1;
	case R_ARCH_INFO_WODST:
		return 0;
	case R_ARCH_INFO_ISVM:
		return 0;
	}
	return 2;
}

static void decode_insn(RAnalOp *op) {
	if (!nios || !nios->cgen_cpu) {
		return;
	}

	CGEN_CPU_DESC cd = nios->cgen_cpu;
	CGEN_FIELDS *fields = &nios->cgen_fields;

	CGEN_FIELDS_BITSIZE (fields) = 16;
	memset (fields, 0, sizeof (*fields));

	CGEN_INSN_INT insn_int = (CGEN_INSN_INT)op->bytes[1] << 8 | op->bytes[0];
	const CGEN_INSN *insn = cgen_lookup_insn (cd, NULL, insn_int, NULL, 16, fields, 0);
	if (!insn || CGEN_INSN_INVALID_P (insn)) {
		return;
	}

	CGEN_EXTRACT_INFO ex_info;
	ex_info.valid = (1 << 16) - 1;
	ex_info.dis_info = NULL;
	ex_info.insn_bytes = (bfd_byte *)op->bytes;

	CGEN_EXTRACT_FN (cd, insn) (cd, insn, &ex_info, insn_int, fields, op->addr);

	int opcode = CGEN_INSN_NUM (insn);
	switch (opcode) {
	case NIOS_INSN_ABS16:
	case NIOS_INSN_ABS32:
		op->type = R_ANAL_OP_TYPE_ABS;
		break;
	case NIOS_INSN_ADD16:
	case NIOS_INSN_ADD32:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case NIOS_INSN_ADDC16:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case NIOS_INSN_ADDI16:
	case NIOS_INSN_ADDI32:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case NIOS_INSN_AND16:
	case NIOS_INSN_AND32:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case NIOS_INSN_ANDN16:
	case NIOS_INSN_ANDN32:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case NIOS_INSN_ASR16:
	case NIOS_INSN_ASR32:
		op->type = R_ANAL_OP_TYPE_SAR;
		break;
	case NIOS_INSN_ASRI16:
	case NIOS_INSN_ASRI32:
		op->type = R_ANAL_OP_TYPE_SAR;
		break;
	case NIOS_INSN_BGEN16:
	case NIOS_INSN_BGEN32:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case NIOS_INSN_BR:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = fields->f_i11_rel;
		break;
	case NIOS_INSN_BSR16:
	case NIOS_INSN_BSR32:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = fields->f_i11_rel;
		break;
	case NIOS_INSN_BSRR16: // In CGEN but not programming guide
		op->type = R_ANAL_OP_TYPE_UCALL;
		op->jump = fields->f_bsrr_i6_rel;
		break;
	case NIOS_INSN_CALL16:
	case NIOS_INSN_CALL32:
		op->type = R_ANAL_OP_TYPE_RCALL;
		op->jump = fields->f_i11_rel;
		break;
	case NIOS_INSN_CALLC16: // In CGEN but not programming guide
		op->type = R_ANAL_OP_TYPE_CCALL;
		op->jump = fields->f_i8v_rel_h;
		op->fail = op->addr + 2;
		break;
	case NIOS_INSN_CALLC32: // In CGEN but not programming guide
		op->type = R_ANAL_OP_TYPE_CCALL;
		op->jump = fields->f_i8v_rel_w;
		op->fail = op->addr + 2;
		break;
	case NIOS_INSN_CMP16:
	case NIOS_INSN_CMP32:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case NIOS_INSN_CMPI16:
	case NIOS_INSN_CMPI32:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case NIOS_INSN_EXT16D:
	case NIOS_INSN_EXT16S:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case NIOS_INSN_EXT8D16:
	case NIOS_INSN_EXT8D32:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case NIOS_INSN_EXT8S16:
	case NIOS_INSN_EXT8S32:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case NIOS_INSN_FILL16:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case NIOS_INSN_FILL816:
	case NIOS_INSN_FILL832:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	// IFS?
	case NIOS_INSN_JMP16:
	case NIOS_INSN_JMP32:
		op->type = R_ANAL_OP_TYPE_RJMP;
		break;
	case NIOS_INSN_JMPC16: // In CGEN but not programming guide
		op->type = R_ANAL_OP_TYPE_RJMP;
		break;
	case NIOS_INSN_JMPC32: // In CGEN but not programming guide
		op->type = R_ANAL_OP_TYPE_RJMP;
		break;
	case NIOS_INSN_LD16:
	case NIOS_INSN_LD32:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case NIOS_INSN_LDP16:
	case NIOS_INSN_LDP32:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case NIOS_INSN_LDS16:
	case NIOS_INSN_LDS32:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case NIOS_INSN_LSL16:
	case NIOS_INSN_LSL32:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case NIOS_INSN_LSLI16:
	case NIOS_INSN_LSLI32:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case NIOS_INSN_LSR16:
	case NIOS_INSN_LSR32:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case NIOS_INSN_LSRI16:
	case NIOS_INSN_LSRI32:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case NIOS_INSN_MOV16:
	case NIOS_INSN_MOV32:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case NIOS_INSN_MOVHI:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case NIOS_INSN_MOVI16:
	case NIOS_INSN_MOVI32:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case NIOS_INSN_MSTEP32:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case NIOS_INSN_MUL32:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case NIOS_INSN_NEG16:
	case NIOS_INSN_NEG32:
		op->type = R_ANAL_OP_TYPE_CPL;
		break;
	case NIOS_INSN_NOT16:
	case NIOS_INSN_NOT32:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case NIOS_INSN_OR16:
	case NIOS_INSN_OR32:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case NIOS_INSN_PFX:
	case NIOS_INSN_PFXIO:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case NIOS_INSN_RDCTL16:
	case NIOS_INSN_RDCTL32:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case NIOS_INSN_RESTORE16:
	case NIOS_INSN_RESTORE32:
		op->type = R_ANAL_OP_TYPE_POP;
		break;
	case NIOS_INSN_RLC16:
	case NIOS_INSN_RLC32:
		op->type = R_ANAL_OP_TYPE_ROL;
		break;
	case NIOS_INSN_RRC16:
	case NIOS_INSN_RRC32:
		op->type = R_ANAL_OP_TYPE_ROR;
		break;
	case NIOS_INSN_SAVE16:
		op->stackop = R_ANAL_STACK_SET;
		op->stackptr = (st64)fields->f_i8v * 2;
		op->type = R_ANAL_OP_TYPE_PUSH;
		break;
	case NIOS_INSN_SAVE32:
		op->stackop = R_ANAL_STACK_SET;
		op->stackptr = (st64)fields->f_i8v * 4;
		op->type = R_ANAL_OP_TYPE_PUSH;
		break;
	case NIOS_INSN_SEXT16:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case NIOS_INSN_SEXT816:
	case NIOS_INSN_SEXT832:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case NIOS_INSN_SKP016:
	case NIOS_INSN_SKP032:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 4;
		op->fail = op->addr + 2;
		break;
	case NIOS_INSN_SKP116:
	case NIOS_INSN_SKP132:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 4;
		op->fail = op->addr + 2;
		break;
	case NIOS_INSN_SKPRNZ16:
	case NIOS_INSN_SKPRNZ32:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 4;
		op->fail = op->addr + 2;
		break;
	case NIOS_INSN_SKPRZ16:
	case NIOS_INSN_SKPRZ32:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 4;
		op->fail = op->addr + 2;
		break;
	case NIOS_INSN_SKPS16:
	case NIOS_INSN_SKPS32:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + 4;
		op->fail = op->addr + 2;
		break;
	case NIOS_INSN_ST16:
	case NIOS_INSN_ST32:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case NIOS_INSN_ST16D:
	case NIOS_INSN_ST16S:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case NIOS_INSN_ST8D16:
	case NIOS_INSN_ST8D32:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case NIOS_INSN_ST8S16:
	case NIOS_INSN_ST8S32:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case NIOS_INSN_STP16:
	case NIOS_INSN_STP32:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case NIOS_INSN_STS16:
	case NIOS_INSN_STS32:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case NIOS_INSN_STS16S:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case NIOS_INSN_STS8S16:
	case NIOS_INSN_STS8S32:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case NIOS_INSN_SUB16:
	case NIOS_INSN_SUB32:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case NIOS_INSN_SUBC16:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case NIOS_INSN_SUBI16:
	case NIOS_INSN_SUBI32:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case NIOS_INSN_SWAP32:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case NIOS_INSN_TRAP16:
	case NIOS_INSN_TRAP32:
		op->type = R_ANAL_OP_TYPE_TRAP;
		op->val = fields->f_i6v;
		break;
	case NIOS_INSN_TRET16:
	case NIOS_INSN_TRET32:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case NIOS_INSN_USR016:
	case NIOS_INSN_USR032:
		op->type = R_ANAL_OP_TYPE_IO;
		break;
	case NIOS_INSN_USR116:
	case NIOS_INSN_USR132:
		op->type = R_ANAL_OP_TYPE_IO;
		break;
	case NIOS_INSN_USR216:
	case NIOS_INSN_USR232:
		op->type = R_ANAL_OP_TYPE_IO;
		break;
	case NIOS_INSN_USR316:
	case NIOS_INSN_USR332:
		op->type = R_ANAL_OP_TYPE_IO;
		break;
	case NIOS_INSN_USR416:
	case NIOS_INSN_USR432:
		op->type = R_ANAL_OP_TYPE_IO;
		break;
	case NIOS_INSN_WRCTL16:
	case NIOS_INSN_WRCTL32:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case NIOS_INSN_XOR16:
	case NIOS_INSN_XOR32:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	default:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	}
}

static int nios_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, struct disassemble_info *info) {
	if (info && info->buffer && length <= 4) {
		memcpy (myaddr, info->buffer, length);
		return 0;
	}
	return -1;
}

static int nios_symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void nios_memory_error(int status, bfd_vma memaddr, struct disassemble_info *info) {
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC_NOGLOBALS()
DECLARE_GENERIC_FPRINTF_FUNC_NOGLOBALS()

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	if (!as || !op || !op->bytes) {
		return false;
	}

	const ut64 addr = op->addr;
	const ut8 *b = op->bytes;

	if (op->size < 2) {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			R_FREE (op->mnemonic);
			op->mnemonic = strdup ("truncated");
		}
		op->type = R_ANAL_OP_TYPE_ILL;
		return false;
	}

	op->size = 2;

	if (!nios || !nios->cgen_cpu) {
		return false;
	}

	decode_insn (op);

	if (mask & R_ARCH_OP_MASK_DISASM) {
		ut8 buf[2] = { b[0], b[1] };
		RStrBuf *sb = r_strbuf_new ("");

		struct disassemble_info di = { 0 };
		di.disassembler_options = "";
		di.mach = as->config->bits == 16? MACH_NIOS16: MACH_NIOS32;
		di.endian = BFD_ENDIAN_LITTLE;
		di.buffer = buf;
		di.buffer_vma = addr;
		di.read_memory_func = &nios_buffer_read_memory;
		di.symbol_at_address_func = &nios_symbol_at_address;
		di.memory_error_func = &nios_memory_error;
		di.print_address_func = &generic_print_address_func;
		di.fprintf_func = &generic_fprintf_func;
		di.stream = sb;

		int len = print_insn_nios ((bfd_vma)addr, &di);

		char *instr = r_strbuf_drain (sb);
		op->size = len > 0? (size_t)len: 2;

		if (len <= 0 || (instr && *instr == '0')) {
			R_FREE (op->mnemonic);
			op->mnemonic = strdup ("invalid");
			op->type = R_ANAL_OP_TYPE_ILL;
			op->size = 2;
			free (instr);
			return false;
		}
		op->mnemonic = instr;
	}

	return true;
}

static bool init(RArchSession *as) {
	if (!as) {
		return false;
	}

	if (!nios) {
		nios = calloc (1, sizeof (*nios));
		if (!nios) {
			return false;
		}

		int bits = as->config? as->config->bits: 32;
		const char *cpu_name = bits == 16? "nios16": "nios32";

		nios->cgen_cpu = nios_cgen_cpu_open_1 (cpu_name, CGEN_ENDIAN_LITTLE);
		if (!nios->cgen_cpu) {
			free (nios);
			nios = NULL;
			return false;
		}

		nios_cgen_init_dis (nios->cgen_cpu);
		cgen_set_parse_operand_fn (nios->cgen_cpu, nios_parse_operand);
	}

	return true;
}

static bool fini(RArchSession *as) {
	if (nios) {
		if (nios->cgen_cpu) {
			nios_cgen_cpu_close (nios->cgen_cpu);
		}
		free (nios);
		nios = NULL;
	}
	return true;
}

const RArchPlugin r_arch_plugin_nios_gnu = {
	.meta = {
		.name = "nios.gnu",
		.desc = "Altera Nios FPGA processor",
		.author = "Christopher Hewitt",
		.license = "LGPL-3.0-only",
	},
	.arch = "nios",
	.endian = R_SYS_ENDIAN_LITTLE,
	.bits = R_SYS_BITS_PACK2 (16, 32),
	.info = archinfo,
	.regs = regs,
	.init = init,
	.fini = fini,
	.decode = decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = (void *)&r_arch_plugin_nios_gnu,
	.version = R2_VERSION,
};
#endif
