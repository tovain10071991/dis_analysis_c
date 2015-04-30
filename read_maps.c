#include <sys/ptrace.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/user.h>
#include <gelf.h>
#include <fcntl.h>
#include <udis86.h>
#include <string.h>

#include "mnemonic.h"

typedef Elf32_Addr UINT_T;
typedef unsigned int UINT_T;
typedef unsigned short USHORT_T;
typedef Elf32_Half USHORT_T;

#define is_branch(ud_obj) \
	(ud_insn_mnemonic(ud_obj)==UD_Icall || ud_insn_mnemonic(ud_obj)==UD_Iiretw || ud_insn_mnemonic(ud_obj)==UD_Iiretd || ud_insn_mnemonic(ud_obj)==UD_Iiretq || (ud_insn_mnemonic(ud_obj)>=UD_Ijo && ud_insn_mnemonic(ud_obj)<=UD_Ijmp) || ud_insn_mnemonic(ud_obj)==UD_Iret || ud_insn_mnemonic(ud_obj)==UD_Iretf)


void set_break_recover(int pid, UINT_T addr, UINT_T* breakpoint, struct user_regs_struct* regs)
{
	//设置断点
	//将addr的头一个字节(第一个字的低字节)换成0xCC
	*breakpoint=ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
	UINT_T temp = *breakpoint & 0xFFFFFF00 | 0xCC;
	ptrace(PTRACE_POKETEXT, pid, addr, temp);

	//执行子进程
	ptrace(PTRACE_CONT, pid, 0, 0);
	wait(NULL);
	printf("meet breakpoint!\n");

	//恢复断点
	ptrace(PTRACE_GETREGS, pid, NULL, regs);
	//软件断点会在断点的下一个字节停住,所以还要将EIP向前恢复一个字节
	regs->eip-=1;
	ptrace(PTRACE_SETREGS, pid, NULL, regs);
	ptrace(PTRACE_POKETEXT, pid, regs->eip, *breakpoint);
}

int main()
{
	int pid;

	UINT_T breakpoint;

	UINT_T got_plt_addr;
	UINT_T plt_min;
	UINT_T plt_max;
	UINT_T entry;

	struct user_regs_struct regs;

	int input_elf;
	Elf* elf;
	GElf_Ehdr ehdr;
	GElf_Phdr phdr;
	GElf_Shdr shdr;
	FILE* input_udis;
	FILE* output;
	ud_t ud_obj;
	UINT_T shdrstr_offset;
	Elf_Scn* scn=NULL;
	if((pid=fork())==0)
	{
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		printf("Hello! I'm child: %d\n", getpid());
		execl("/bin/ls", "ls", NULL);
	}
	else
	{
		wait(NULL);
		printf("Hello! I'm parent!\n");
		
		input_elf = open("/bin/ls", O_RDONLY, 0);
		input_udis = fopen("/bin/ls", "r");
		output = fopen("ls.dis", "w");

		//现在读取主执行模块的入口地址.似乎只有库模块的地址是可以随机化的,这里从ELF文件中读取入口地址
		elf_version(EV_CURRENT);
		elf = elf_begin(input_elf, ELF_C_READ, NULL);
		gelf_getehdr(elf, &ehdr);
		
		entry = ehdr.e_entry;

		//首先找到plt的地址范围和got.plt的地址吧
		//先找节名表吧
		size_t shdrstrndx;
		elf_getshdrstrndx(elf, &shdrstrndx);
		Elf_Scn* shdrstrscn = elf_getscn(elf, shdrstrndx);
		GElf_Shdr shdrstr;
		gelf_getshdr(shdrstrscn, &shdrstr);
		shdrstr_offset = shdrstr.sh_offset;
		while((scn=elf_nextscn(elf, scn))!=NULL)
		{
			gelf_getshdr(scn, &shdr);
			char* name;
			name = elf_strptr(elf, shdrstrndx, shdr.sh_name);
			printf("%s\n", name);
			if(!strcmp(name,".plt"))
			{
				plt_min=shdr.sh_addr;
				plt_max=shdr.sh_addr+shdr.sh_size;
				printf("%x, %x\n", plt_min, plt_max);
			}
			if(!strcmp(name,".got.plt"))
			{
				got_plt_addr = shdr.sh_addr;
				printf("%x\n", got_plt_addr);
			}
		}
		
		set_break_recover(pid, entry, &breakpoint, &regs);

		//返汇编一个trace
		int i;
		for(i=0;i<ehdr.e_phnum;i++)
		{
			gelf_getphdr(elf, i, &phdr);
			if(entry>=phdr.p_vaddr&&entry<=phdr.p_vaddr+phdr.p_memsz)
				break;
		}
		UINT_T offset = entry-(phdr.p_vaddr-phdr.p_offset);
		ud_t ud_obj;
		ud_init(&ud_obj);
		ud_set_input_file(&ud_obj, input_udis);
	    ud_set_mode(&ud_obj, 32);
	    ud_set_syntax(&ud_obj, UD_SYN_ATT);
		ud_set_pc(&ud_obj, entry);
		ud_input_skip(&ud_obj, offset);

		fprintf(output, "ADDR      \tHEX                 \tTYPE            \tOPERAND\tINS\n");
		while (ud_disassemble(&ud_obj))
		{
			if(ud_insn_off(&ud_obj)> phdr.p_vaddr+phdr.p_memsz)
				break;
			const ud_operand_t* opr = ud_insn_opr(&ud_obj, 0);
			fprintf(output, "0x%-8llx\t%-20s\t%-16s\t%d\t%s\n", ud_insn_off(&ud_obj), ud_insn_hex(&ud_obj), mnemonic_name[ud_insn_mnemonic(&ud_obj)], opr->type, ud_insn_asm(&ud_obj));
			if(is_branch(&ud_obj))
				break;
	    }
		if(ud_insn_off(&ud_obj)> phdr.p_vaddr+phdr.p_memsz)
			ptrace(PTRACE_KILL, pid, 0, 0);

		//反汇编到分支指令,在这里设置断点
		set_break_recover(pid, ud_insn_off(&ud_obj), &breakpoint, &regs);

		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		printf("eax\tebx\tecx\tedx\tesi\tedi\tesp\tebp\teip\n0x%.8lx\t0x%.8lx\t0x%.8lx\t0x%.8lx\t0x%.8lx\t0x%.8lx\t0x%.8lx\t0x%.8lx\t0x%.8lx\n", regs.eax, regs.ebx, regs.ecx, regs.edx, regs.esi, regs.edi, regs.esp, regs.ebp, regs.eip);

		//查找目标地址,判断目标地址是不是plt段,是的话找到要修改的got.plt表的地址,如果其中值不为目标地址,则等待修改,否则就直接跳转到目标地址
		


		//下面判断目标地址是不是在plt段
		

		ptrace(PTRACE_KILL, pid, 0, 0);
	}
	return 0;
}
