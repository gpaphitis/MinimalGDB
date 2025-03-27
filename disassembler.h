#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <capstone/capstone.h>
#include "breakpoints.h"
#include "elfloader.h"

int initialize_disassembler();
int is_cs_cflow_group(uint8_t g);
int is_cs_cflow_ins(cs_insn *ins);
uint64_t get_cs_ins_immediate_target(cs_insn *ins);
void disas(list_t *breakpoints, unsigned char *buffer, unsigned int size, long address, long offset, int count);
void destroy_disassembler();

#endif