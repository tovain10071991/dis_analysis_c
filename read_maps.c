#include <sys/ptrace.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/user.h>
#include <gelf.h>
#include <fcntl.h>
#include <udis86.h>
#include <string.h>
#include <stdlib.h>

#include "mnemonic.h"
#include "sec_index.h"

typedef Elf32_Addr UINT_T;
typedef unsigned int UINT_T;
typedef unsigned short USHORT_T;
typedef Elf32_Half USHORT_T;

#define is_branch(ud_obj) \
	(ud_insn_mnemonic(ud_obj)==UD_Icall || ud_insn_mnemonic(ud_obj)==UD_Iiretw || ud_insn_mnemonic(ud_obj)==UD_Iiretd || ud_insn_mnemonic(ud_obj)==UD_Iiretq || (ud_insn_mnemonic(ud_obj)>=UD_Ijo && ud_insn_mnemonic(ud_obj)<=UD_Ijmp) || ud_insn_mnemonic(ud_obj)==UD_Iret || ud_insn_mnemonic(ud_obj)==UD_Iretf)

#define SET_SEC_INFO(name) \
	if(!strcmp(sec_name+1, #name)){ \
		sec_info[name##_addr] = shdr.sh_addr; \
		sec_info[name##_offset] = shdr.sh_offset; \
		sec_info[name##_size] = shdr.sh_size; \
		printf("Succeed\n"); \
		continue; \
	}

UINT_T sec_info[index_max];

UINT_T breakpoint;		//断点地址
//UINT_T got_plt_addr;	//.got.plt表的基址
//UINT_T got_plt_off;		//.got.plt表的文件偏移
//UINT_T plt_min;			//.plt表的基址
//UINT_T plt_max;			//.plt表的尾址
//UINT_T plt_off;			//.plt表的文件偏移
//UINT_T entry;			//主模块的入口地址
struct user_regs_struct regs;
//用于libelf的变量
int input_elf;
Elf* elf;
GElf_Ehdr ehdr;
GElf_Phdr phdr;
GElf_Shdr shdr;
Elf_Scn* scn;
size_t shdrstrndx;		//节名符号表索引
GElf_Shdr shdrstr;		//节名符号表头项
//用于liibudis的变量
FILE* input_udis;
ud_t ud_obj;
const ud_operand_t* opr;
//输出文件
FILE* output;

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

void get_sec_info()
{
	sec_info[entry_addr] = ehdr.e_entry;

	//初始化各种偏移和地址
	//初始化shdrstrndx
	elf_getshdrstrndx(elf, &shdrstrndx);
	//初始化shdrstr
	Elf_Scn* shdrstrscn = elf_getscn(elf, shdrstrndx);
	gelf_getshdr(shdrstrscn, &shdrstr);
	//找到.plt表和.got.plt表并初始化地址
	scn=NULL;
	while((scn=elf_nextscn(elf, scn))!=NULL)
	{
		gelf_getshdr(scn, &shdr);
		char* sec_name;
		sec_name = elf_strptr(elf, shdrstrndx, shdr.sh_name);
		SET_SEC_INFO(dynsym)
		SET_SEC_INFO(init)
		SET_SEC_INFO(plt)
		SET_SEC_INFO(text)
		SET_SEC_INFO(fini)
		SET_SEC_INFO(got)
		SET_SEC_INFO(got_plt)
		SET_SEC_INFO(data)
	}
	return;
}

inline void par_process(int pid)
{
//	UINT_T offset;			//入口指令的文件偏移

	wait(NULL);
	printf("Hello! I'm parent!\n");
	//设置文件描述符
	input_elf = open("/bin/ls", O_RDONLY, 0);
	input_udis = fopen("/bin/ls", "r");
	output = fopen("ls.dis", "w");

	//初始化libelf,读取主执行模块的入口地址.似乎只有库模块的地址是可以随机化的,这里从ELF文件中读取入口地址
	elf_version(EV_CURRENT);
	elf = elf_begin(input_elf, ELF_C_READ, NULL);
	gelf_getehdr(elf, &ehdr);

	get_sec_info();

/*	entry = ehdr.e_entry;

	//初始化各种偏移和地址
	//初始化plt_addr, got_plt_addr, shdrstrndx, shdrstr
	//初始化shdrstrndx
	elf_getshdrstrndx(elf, &shdrstrndx);
	//初始化shdrstr
	Elf_Scn* shdrstrscn = elf_getscn(elf, shdrstrndx);
	gelf_getshdr(shdrstrscn, &shdrstr);
	//找到.plt表和.got.plt表并初始化地址
	scn=NULL;
	while((scn=elf_nextscn(elf, scn))!=NULL)
	{
		gelf_getshdr(scn, &shdr);
		char* sec_name;
		sec_name = elf_strptr(elf, shdrstrndx, shdr.sh_name);
		if(!strcmp(sec_name,".plt"))
		{
			plt_min = shdr.sh_addr;
			plt_max = shdr.sh_addr+shdr.sh_size;
			plt_off = shdr.sh_offset;
			printf("%s: 0x%x, 0x%x\n", sec_name, plt_min, plt_max);
		}
		if(!strcmp(sec_name,".got.plt"))
		{
			got_plt_addr = shdr.sh_addr;
			got_plt_off = shdr.sh_offset;
			printf("%s: 0x%x\n", sec_name, got_plt_addr);
		}
	}
	
*/	set_break_recover(pid, sec_info[entry_addr], &breakpoint, &regs);

	//返汇编一个trace
	int i;
	for(i=0;i<ehdr.e_phnum;i++)
	{
		gelf_getphdr(elf, i, &phdr);
		if(sec_info[entry_addr]>=phdr.p_vaddr&&sec_info[entry_addr]<=phdr.p_vaddr+phdr.p_memsz)
			break;
	}
	sec_info[entry_offset] = sec_info[entry_addr]-(phdr.p_vaddr-phdr.p_offset);
	ud_init(&ud_obj);
	ud_set_input_file(&ud_obj, input_udis);
	ud_set_mode(&ud_obj, 32);
	ud_set_syntax(&ud_obj, UD_SYN_ATT);
	ud_set_pc(&ud_obj, sec_info[entry_addr]);
	ud_input_skip(&ud_obj, sec_info[entry_offset]);

	fprintf(output, "ADDR      \tHEX                 \tTYPE            \tINS\n");
	while (ud_disassemble(&ud_obj))
	{
		if(ud_insn_off(&ud_obj)> phdr.p_vaddr+phdr.p_memsz)
			break;
		fprintf(output, "0x%-8llx\t%-20s\t%-16s\t%s\n", ud_insn_off(&ud_obj), ud_insn_hex(&ud_obj), mnemonic_name[ud_insn_mnemonic(&ud_obj)], ud_insn_asm(&ud_obj));
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
	opr = ud_insn_opr(&ud_obj, 0);
	if(opr->type!=UD_OP_JIMM)
	{
		printf("Error: %s\n", ud_insn_asm(&ud_obj));
	}
	UINT_T addr = ud_insn_off(&ud_obj)+ud_insn_len(&ud_obj)+opr->lval.sdword;
	printf("%x\n", addr);
//	if(addr<=plt_min||addr>=plt_max)
//		printf("not in plt\n");
	//先把来把目标的指令汇编看看
	lseek(input_elf, addr-0x8048000, SEEK_SET);
	void* buf = (char*)malloc(6);
	read(input_elf, buf, 6);
	ud_set_input_buffer(&ud_obj, buf, 6);
	ud_disassemble(&ud_obj);
	fprintf(output, "0x%-8llx\t%-20s\t%-16s\t%s\n", ud_insn_off(&ud_obj), ud_insn_hex(&ud_obj), mnemonic_name[ud_insn_mnemonic(&ud_obj)], ud_insn_asm(&ud_obj));
	//看看操作数是怎样的
	opr = ud_insn_opr(&ud_obj, 0);
	printf("%x\n",got_plt_addr);
	lseek(input_elf, opr->lval.sdword-sec_info[got_plt_addr]+sec_info[got_plt_offset], SEEK_SET);
	UINT_T* ptr = (UINT_T*)malloc(4);
	read(input_elf, ptr, 4);
	printf("%x\n", *ptr);
	UINT_T data;
	while(1){
		ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
		data = ptrace(PTRACE_PEEKTEXT, pid, opr->lval.sdword, 0);
		if(data!=0xffffffff&&data!=*ptr)
		{
			printf("%x\n", data);
			break;
		}
	}
	ptrace(PTRACE_KILL, pid, 0, 0);
}

int main()
{
	int pid;

	//fork进程
	if((pid=fork())==0)
	{
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		printf("Hello! I'm child: %d\n", getpid());
		execl("/bin/ls", "ls", NULL);
	}
	else
	{
		//父进程的工作
		par_process(pid);
	}
	return 0;
}
