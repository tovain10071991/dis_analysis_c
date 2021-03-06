#ifndef _MNEMONIC_H_
#define _MNEMONIC_H_

char* mnemonic_name[]={
	"invalid",
	"3dnow",
	"none",
	"db",
	"pause",
	"aaa",
	"aad",
	"aam",
	"aas",
	"adc",
	"add",
	"addpd",
	"addps",
	"addsd",
	"addss",
	"and",
	"andpd",
	"andps",
	"andnpd",
	"andnps",
	"arpl",
	"movsxd",
	"bound",
	"bsf",
	"bsr",
	"bswap",
	"bt",
	"btc",
	"btr",
	"bts",
	"call",
	"cbw",
	"cwde",
	"cdqe",
	"clc",
	"cld",
	"clflush",
	"clgi",
	"cli",
	"clts",
	"cmc",
	"cmovo",
	"cmovno",
	"cmovb",
	"cmovae",
	"cmovz",
	"cmovnz",
	"cmovbe",
	"cmova",
	"cmovs",
	"cmovns",
	"cmovp",
	"cmovnp",
	"cmovl",
	"cmovge",
	"cmovle",
	"cmovg",
	"cmp",
	"cmppd",
	"cmpps",
	"cmpsb",
	"cmpsw",
	"cmpsd",
	"cmpsq",
	"cmpss",
	"cmpxchg",
	"cmpxchg8b",
	"cmpxchg16b",
	"comisd",
	"comiss",
	"cpuid",
	"cvtdq2pd",
	"cvtdq2ps",
	"cvtpd2dq",
	"cvtpd2pi",
	"cvtpd2ps",
	"cvtpi2ps",
	"cvtpi2pd",
	"cvtps2dq",
	"cvtps2pi",
	"cvtps2pd",
	"cvtsd2si",
	"cvtsd2ss",
	"cvtsi2ss",
	"cvtss2si",
	"cvtss2sd",
	"cvttpd2pi",
	"cvttpd2dq",
	"cvttps2dq",
	"cvttps2pi",
	"cvttsd2si",
	"cvtsi2sd",
	"cvttss2si",
	"cwd",
	"cdq",
	"cqo",
	"daa",
	"das",
	"dec",
	"div",
	"divpd",
	"divps",
	"divsd",
	"divss",
	"emms",
	"enter",
	"f2xm1",
	"fabs",
	"fadd",
	"faddp",
	"fbld",
	"fbstp",
	"fchs",
	"fclex",
	"fcmovb",
	"fcmove",
	"fcmovbe",
	"fcmovu",
	"fcmovnb",
	"fcmovne",
	"fcmovnbe",
	"fcmovnu",
	"fucomi",
	"fcom",
	"fcom2",
	"fcomp3",
	"fcomi",
	"fucomip",
	"fcomip",
	"fcomp",
	"fcomp5",
	"fcompp",
	"fcos",
	"fdecstp",
	"fdiv",
	"fdivp",
	"fdivr",
	"fdivrp",
	"femms",
	"ffree",
	"ffreep",
	"ficom",
	"ficomp",
	"fild",
	"fincstp",
	"fninit",
	"fiadd",
	"fidivr",
	"fidiv",
	"fisub",
	"fisubr",
	"fist",
	"fistp",
	"fisttp",
	"fld",
	"fld1",
	"fldl2t",
	"fldl2e",
	"fldpi",
	"fldlg2",
	"fldln2",
	"fldz",
	"fldcw",
	"fldenv",
	"fmul",
	"fmulp",
	"fimul",
	"fnop",
	"fpatan",
	"fprem",
	"fprem1",
	"fptan",
	"frndint",
	"frstor",
	"fnsave",
	"fscale",
	"fsin",
	"fsincos",
	"fsqrt",
	"fstp",
	"fstp1",
	"fstp8",
	"fstp9",
	"fst",
	"fnstcw",
	"fnstenv",
	"fnstsw",
	"fsub",
	"fsubp",
	"fsubr",
	"fsubrp",
	"ftst",
	"fucom",
	"fucomp",
	"fucompp",
	"fxam",
	"fxch",
	"fxch4",
	"fxch7",
	"fxrstor",
	"fxsave",
	"fxtract",
	"fyl2x",
	"fyl2xp1",
	"hlt",
	"idiv",
	"in",
	"imul",
	"inc",
	"insb",
	"insw",
	"insd",
	"int1",
	"int3",
	"int",
	"into",
	"invd",
	"invept",
	"invlpg",
	"invlpga",
	"invvpid",
	"iretw",
	"iretd",
	"iretq",
	"jo",
	"jno",
	"jb",
	"jae",
	"jz",
	"jnz",
	"jbe",
	"ja",
	"js",
	"jns",
	"jp",
	"jnp",
	"jl",
	"jge",
	"jle",
	"jg",
	"jcxz",
	"jecxz",
	"jrcxz",
	"jmp",
	"lahf",
	"lar",
	"lddqu",
	"ldmxcsr",
	"lds",
	"lea",
	"les",
	"lfs",
	"lgs",
	"lidt",
	"lss",
	"leave",
	"lfence",
	"lgdt",
	"lldt",
	"lmsw",
	"lock",
	"lodsb",
	"lodsw",
	"lodsd",
	"lodsq",
	"loopne",
	"loope",
	"loop",
	"lsl",
	"ltr",
	"maskmovq",
	"maxpd",
	"maxps",
	"maxsd",
	"maxss",
	"mfence",
	"minpd",
	"minps",
	"minsd",
	"minss",
	"monitor",
	"montmul",
	"mov",
	"movapd",
	"movaps",
	"movd",
	"movhpd",
	"movhps",
	"movlhps",
	"movlpd",
	"movlps",
	"movhlps",
	"movmskpd",
	"movmskps",
	"movntdq",
	"movnti",
	"movntpd",
	"movntps",
	"movntq",
	"movq",
	"movsb",
	"movsw",
	"movsd",
	"movsq",
	"movss",
	"movsx",
	"movupd",
	"movups",
	"movzx",
	"mul",
	"mulpd",
	"mulps",
	"mulsd",
	"mulss",
	"mwait",
	"neg",
	"nop",
	"not",
	"or",
	"orpd",
	"orps",
	"out",
	"outsb",
	"outsw",
	"outsd",
	"packsswb",
	"packssdw",
	"packuswb",
	"paddb",
	"paddw",
	"paddd",
	"paddsb",
	"paddsw",
	"paddusb",
	"paddusw",
	"pand",
	"pandn",
	"pavgb",
	"pavgw",
	"pcmpeqb",
	"pcmpeqw",
	"pcmpeqd",
	"pcmpgtb",
	"pcmpgtw",
	"pcmpgtd",
	"pextrb",
	"pextrd",
	"pextrq",
	"pextrw",
	"pinsrb",
	"pinsrw",
	"pinsrd",
	"pinsrq",
	"pmaddwd",
	"pmaxsw",
	"pmaxub",
	"pminsw",
	"pminub",
	"pmovmskb",
	"pmulhuw",
	"pmulhw",
	"pmullw",
	"pop",
	"popa",
	"popad",
	"popfw",
	"popfd",
	"popfq",
	"por",
	"prefetch",
	"prefetchnta",
	"prefetcht0",
	"prefetcht1",
	"prefetcht2",
	"psadbw",
	"pshufw",
	"psllw",
	"pslld",
	"psllq",
	"psraw",
	"psrad",
	"psrlw",
	"psrld",
	"psrlq",
	"psubb",
	"psubw",
	"psubd",
	"psubsb",
	"psubsw",
	"psubusb",
	"psubusw",
	"punpckhbw",
	"punpckhwd",
	"punpckhdq",
	"punpcklbw",
	"punpcklwd",
	"punpckldq",
	"pi2fw",
	"pi2fd",
	"pf2iw",
	"pf2id",
	"pfnacc",
	"pfpnacc",
	"pfcmpge",
	"pfmin",
	"pfrcp",
	"pfrsqrt",
	"pfsub",
	"pfadd",
	"pfcmpgt",
	"pfmax",
	"pfrcpit1",
	"pfrsqit1",
	"pfsubr",
	"pfacc",
	"pfcmpeq",
	"pfmul",
	"pfrcpit2",
	"pmulhrw",
	"pswapd",
	"pavgusb",
	"push",
	"pusha",
	"pushad",
	"pushfw",
	"pushfd",
	"pushfq",
	"pxor",
	"rcl",
	"rcr",
	"rol",
	"ror",
	"rcpps",
	"rcpss",
	"rdmsr",
	"rdpmc",
	"rdtsc",
	"rdtscp",
	"repne",
	"rep",
	"ret",
	"retf",
	"rsm",
	"rsqrtps",
	"rsqrtss",
	"sahf",
	"salc",
	"sar",
	"shl",
	"shr",
	"sbb",
	"scasb",
	"scasw",
	"scasd",
	"scasq",
	"seto",
	"setno",
	"setb",
	"setae",
	"setz",
	"setnz",
	"setbe",
	"seta",
	"sets",
	"setns",
	"setp",
	"setnp",
	"setl",
	"setge",
	"setle",
	"setg",
	"sfence",
	"sgdt",
	"shld",
	"shrd",
	"shufpd",
	"shufps",
	"sidt",
	"sldt",
	"smsw",
	"sqrtps",
	"sqrtpd",
	"sqrtsd",
	"sqrtss",
	"stc",
	"std",
	"stgi",
	"sti",
	"skinit",
	"stmxcsr",
	"stosb",
	"stosw",
	"stosd",
	"stosq",
	"str",
	"sub",
	"subpd",
	"subps",
	"subsd",
	"subss",
	"swapgs",
	"syscall",
	"sysenter",
	"sysexit",
	"sysret",
	"test",
	"ucomisd",
	"ucomiss",
	"ud2",
	"unpckhpd",
	"unpckhps",
	"unpcklps",
	"unpcklpd",
	"verr",
	"verw",
	"vmcall",
	"vmclear",
	"vmxon",
	"vmptrld",
	"vmptrst",
	"vmlaunch",
	"vmresume",
	"vmxoff",
	"vmread",
	"vmwrite",
	"vmrun",
	"vmmcall",
	"vmload",
	"vmsave",
	"wait",
	"wbinvd",
	"wrmsr",
	"xadd",
	"xchg",
	"xgetbv",
	"xlatb",
	"xor",
	"xorpd",
	"xorps",
	"xcryptecb",
	"xcryptcbc",
	"xcryptctr",
	"xcryptcfb",
	"xcryptofb",
	"xrstor",
	"xsave",
	"xsetbv",
	"xsha1",
	"xsha256",
	"xstore",
	"aesdec",
	"aesdeclast",
	"aesenc",
	"aesenclast",
	"aesimc",
	"aeskeygenassist",
	"pclmulqdq",
	"getsec",
	"movdqa",
	"maskmovdqu",
	"movdq2q",
	"movdqu",
	"movq2dq",
	"paddq",
	"psubq",
	"pmuludq",
	"pshufhw",
	"pshuflw",
	"pshufd",
	"pslldq",
	"psrldq",
	"punpckhqdq",
	"punpcklqdq",
	"addsubpd",
	"addsubps",
	"haddpd",
	"haddps",
	"hsubpd",
	"hsubps",
	"movddup",
	"movshdup",
	"movsldup",
	"pabsb",
	"pabsw",
	"pabsd",
	"pshufb",
	"phaddw",
	"phaddd",
	"phaddsw",
	"pmaddubsw",
	"phsubw",
	"phsubd",
	"phsubsw",
	"psignb",
	"psignd",
	"psignw",
	"pmulhrsw",
	"palignr",
	"pblendvb",
	"pmuldq",
	"pminsb",
	"pminsd",
	"pminuw",
	"pminud",
	"pmaxsb",
	"pmaxsd",
	"pmaxud",
	"pmaxuw",
	"pmulld",
	"phminposuw",
	"roundps",
	"roundpd",
	"roundss",
	"roundsd",
	"blendpd",
	"pblendw",
	"blendps",
	"blendvpd",
	"blendvps",
	"dpps",
	"dppd",
	"mpsadbw",
	"extractps",
	"insertps",
	"movntdqa",
	"packusdw",
	"pmovsxbw",
	"pmovsxbd",
	"pmovsxbq",
	"pmovsxwd",
	"pmovsxwq",
	"pmovsxdq",
	"pmovzxbw",
	"pmovzxbd",
	"pmovzxbq",
	"pmovzxwd",
	"pmovzxwq",
	"pmovzxdq",
	"pcmpeqq",
	"popcnt",
	"ptest",
	"pcmpestri",
	"pcmpestrm",
	"pcmpgtq",
	"pcmpistri",
	"pcmpistrm",
	"movbe",
	"crc32",
	"C_CODE",
};

#endif
