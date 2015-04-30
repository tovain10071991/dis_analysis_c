#ifndef _SEC_INDEX_H_
#define _SEC_INDEX_H_

enum{
	entry_addr,
	entry_offset,
	dynsym_addr,
	dynsym_offset,
	dynsym_size,
	init_addr,
	init_offset,
	init_size,
	plt_addr,
	plt_offset,
	plt_size,
	text_addr,
	text_offset,
	text_size,
	fini_addr,
	fini_offset,
	fini_size,
	got_addr,
	got_offset,
	got_size,
	got_plt_addr,
	got_plt_offset,
	got_plt_size,
	data_addr,
	data_offset,
	data_size,
	index_max,
} sec_index;

#endif
