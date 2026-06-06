/* nios.pseudo plugin by hewittc at 2026 */

#include <r_lib.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_asm.h>

static const char *pseudo_rules[] = {
	/* 0 operands */
		"restore/0/restore()",
		"nop/0/nop()",
		"ret/0/return()",
		"lret/0/return()",

	/* 1 operand */
		"abs/1/$1 = abs($1)",
		"br/1/jump($1)",
		"bsr/1/call($1)",
		"call/1/call($1 << 1)",
		"callc/1/call($1)",
		"clr/1/$1 = 0",
		"dec/1/$1 -= 1",
		"ifrnz/1/if($1 == 0) skip()",
		"ifrz/1/if($1 != 0) skip()",
		"ifs/1/if($1 == 0) skip()",
		"inc/1/$1 += 1",
		"jmp/1/$1 = $1 << 1",
		"jmpc/1/jump($1)",
		"mstep/1/mstep($1)",
		"mul/1/r0 *= $1",
		"neg/1/$1 = -$1",
		"not/1/$1 = ~$1",
		"pfx/1/k = $1",
		"pfxio/1/k = $1",
		"rdctl/1/$1 = rdctl()",
		"rlc/1/rotate_left_c($1)",
		"rrc/1/rotate_right_c($1)",
		"sext16/1/$1 = sign_extend16($1)",
		"sext8/1/$1 = sign_extend8($1)",
		"skprnz/1/if($1 != 0) skip()",
		"skprz/1/if($1 == 0) skip()",
		"skps/1/if($1) skip()",
		"swap/1/swap_halfwords($1)",
		"trap/1/trap($1)",
		"tret/1/return()",
		"usr1/1/usr1($1)",
		"usr2/1/usr2($1)",
		"usr3/1/usr3($1)",
		"usr4/1/usr4($1)",
		"wrctl/1/wrctl($1)",

	/* 2 operands */
		"add/2/$1 += $2",
		"addc/2/$1 += $2 + C",
		"addi/2/$1 += $2",
		"and/2/$1 &= $2",
		"andn/2/$1 &= ~$2",
		"asr/2/$1 >>= $2",
		"asri/2/$1 >>= $2",
		"bgen/2/$1 = $1 = 2**$2",
		"bsrr/2/jump($1, $2)",
		"cmp/2/cmp($1, $2)",
		"cmpi/2/cmp($1, $2)",
		"ext16d/2/$1 = extract16_dynamic($1, $2)",
		"ext16s/2/$1 = extract16_static($1, $2)",
		"ext8d/2/$1 = extract8_dynamic($1, $2)",
		"ext8s/2/$1 = extract8_static($1, $2)",
		"fill16/2/fill16($1)",
		"fill8/2/fill8($1)",
		"if0/2/if(bit($1) == 0) skip()",
		"if1/2/if(bit($1) == 1) skip()",
		"ld/2/$1 = Mem[$2]",
		"ldp/2/$1 = Mem[$2]",
		"lds/2/$1 = Mem[$2]",
		"lsl/2/$1 <<= $2",
		"lsli/2/$1 <<= $2",
		"lsr/2/$1 >>= $2",
		"lsri/2/$1 >>= $2",
		"mov/2/$1 = $2",
		"movhi/2/$1 = ($2 << 16)",
		"movi/2/$1 = $2",
		"or/2/$1 |= $2",
		"save/2/sp = fp - ($2 * 2)",
		"skp0/2/if ($1[$2] == 0) skip()",
		"skp1/2/if ($1[$2] != 0) skip()",
		"st/2/Mem[$1] = $2",
		"st16d/2/Mem[$1] = ($2 & 0xffff)",
		"st8d/2/Mem[$1] = ($2 & 0xff)",
		"stp/2/Mem[$1] = $2",
		"sts/2/Mem[$1] = $2",
		"sts16s/2/Mem[$1] = ($2 & 0xffff)",
		"sts8s/2/Mem[$1] = ($2 & 0xff)",
		"sub/2/$1 -= $2",
		"subc/2/$1 -= $2 + C",
		"subi/2/$1 -= $2",
		"usr0/2/$1 = $2",
		"xor/2/$1 ^= $2",

	/* 3 operands */
		"st16s/3/Mem[$1] = ($2 & 0xffff)",
		"st8s/3/Mem[$1] = ($2 & 0xff)",

	NULL
};

static char *
parse(RAsmPluginSession *aps, const char *data) {
	return r_str_pseudo_transform (pseudo_rules, data);
}

RAsmPlugin r_asm_plugin_nios = {
	.meta = {
		.name = "nios",
		.desc = "Nios pseudo syntax",
		.author = "Christopher Hewitt",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = (void *)&r_asm_plugin_nios,
	.version = R2_VERSION,
};
#endif
