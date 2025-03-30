#include "disassembler.h"
#define TOOL "disassembler"
#define die(...)                              \
   do                                         \
   {                                          \
      fprintf(stderr, TOOL ": " __VA_ARGS__); \
      fputc('\n', stderr);                    \
      exit(EXIT_FAILURE);                     \
   } while (0)

static csh handle;

int initialize_disassembler()
{
   if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
      return -1;

   /* AT&T */
   cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
   cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
   return 0;
}

int is_cs_cflow_group(uint8_t g)
{
   return (g == CS_GRP_JUMP) || (g == CS_GRP_CALL) || (g == CS_GRP_RET) || (g == CS_GRP_IRET);
}

int is_cs_cflow_ins(cs_insn *ins)
{
   for (size_t i = 0; i < ins->detail->groups_count; i++)
   {
      if (is_cs_cflow_group(ins->detail->groups[i]))
      {
         return 1;
      }
   }
   return 0;
}

uint64_t get_cs_ins_immediate_target(cs_insn *ins)
{
   cs_x86_op *cs_op;

   for (size_t i = 0; i < ins->detail->groups_count; i++)
   {
      if (is_cs_cflow_group(ins->detail->groups[i]))
      {
         for (size_t j = 0; j < ins->detail->x86.op_count; j++)
         {
            cs_op = &ins->detail->x86.operands[j];
            if (cs_op->type == X86_OP_IMM)
               return cs_op->imm;
         }
      }
   }
   return 0;
}

void disas(list_t *breakpoints, unsigned char *buffer, unsigned int size, long address, long offset, int count)
{
   cs_insn *insn;
   size_t disassembled_count;

   disassembled_count = cs_disasm(handle, buffer, size, address + offset, count, &insn);
   int bytes_disassembled = 0;
   int breakpoint_found = 0;

   if (disassembled_count > 0)
   {
      size_t j;
      for (j = 0; j < disassembled_count; j++)
      {
         if (!strcmp(insn[j].mnemonic, "int3"))
         {
            breakpoint_found = 1;
            break;
         }
         if (j == 0 && offset == 0)
            fprintf(stderr, "=> ");
         char *symbol = get_symbol(insn[j].address);
         if (symbol == NULL)
            fprintf(stderr, "\x1b[34m0x%" PRIx64 "\x1b[0m:\t", insn[j].address);
         else
            fprintf(stderr, "\x1b[33m%s\x1b[0m :\t", symbol);
         fprintf(stderr, "%s\t\t%s", insn[j].mnemonic,
                 insn[j].op_str);
         if (is_cs_cflow_ins(&insn[j]))
         {
            uint64_t target = get_cs_ins_immediate_target(&insn[j]);
            char *symbol = get_symbol(target);
            if (symbol != NULL && strcmp(symbol, ""))
               fprintf(stderr, " # <\x1b[33m%s\x1b[0m>", symbol);
         }
         fprintf(stderr, "\n");
         bytes_disassembled += insn[j].size;
         if (insn[j].id == X86_INS_RET)
            break;
      }
      cs_free(insn, disassembled_count);
      if (breakpoint_found)
      {
         breakpoint_t *disassembled_breakpoint = get_breakpoint_by_address(breakpoints, address + offset + bytes_disassembled);
         buffer[bytes_disassembled] &= 0x00;
         buffer[bytes_disassembled] |= (disassembled_breakpoint->previous_code & 0xFF);
         disas(breakpoints, &buffer[bytes_disassembled], size, address, bytes_disassembled + offset, count - j);
      }
   }
   else
      fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
}

void destroy_disassembler()
{
   cs_close(&handle);
}