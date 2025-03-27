#include "elfloader.h"
#define TOOL "elfloader"
#define die(...)                              \
   do                                         \
   {                                          \
      fprintf(stderr, TOOL ": " __VA_ARGS__); \
      fputc('\n', stderr);                    \
      exit(EXIT_FAILURE);                     \
   } while (0)

static Elf *elf;

int initialize_elf_engine(char *filename)
{
   int fd = open(filename, O_RDONLY);

   elf = elf_begin(fd, ELF_C_READ, NULL);
   if (!elf)
      return -1;
   return 0;
}

char *get_symbol(long address)
{
   Elf_Scn *scn = NULL;
   GElf_Shdr shdr;
   size_t shstrndx;
   Elf_Data *data;
   int count = 0;
   if (elf_getshdrstrndx(elf, &shstrndx) != 0)
      die("(getshdrstrndx) %s", elf_errmsg(-1));
   while ((scn = elf_nextscn(elf, scn)) != NULL)
   {
      if (gelf_getshdr(scn, &shdr) != &shdr)
         die("(getshdr) %s", elf_errmsg(-1));
      /* Locate symbol table.  */
      if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".symtab"))
      {
         data = elf_getdata(scn, NULL);
         count = shdr.sh_size / shdr.sh_entsize;

         for (int i = 0; i < count; ++i)
         {
            GElf_Sym sym;
            gelf_getsym(data, i, &sym);
            if (address == sym.st_value)
               return elf_strptr(elf, shdr.sh_link, sym.st_name);
         }
      }
   }
   return NULL;
}
long get_symbol_value(const char *symbol)
{
   Elf_Scn *scn = NULL;
   GElf_Shdr shdr;
   size_t shstrndx;
   Elf_Data *data;
   int count = 0;
   if (elf_getshdrstrndx(elf, &shstrndx) != 0)
      die("(getshdrstrndx) %s", elf_errmsg(-1));
   while ((scn = elf_nextscn(elf, scn)) != NULL)
   {
      if (gelf_getshdr(scn, &shdr) != &shdr)
         die("(getshdr) %s", elf_errmsg(-1));
      /* Locate symbol table.  */
      if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".symtab"))
      {
         data = elf_getdata(scn, NULL);
         count = shdr.sh_size / shdr.sh_entsize;

         for (int i = 0; i < count; ++i)
         {
            GElf_Sym sym;
            gelf_getsym(data, i, &sym);
            if (!strcmp(symbol, elf_strptr(elf, shdr.sh_link, sym.st_name)))
               return sym.st_value;
         }
      }
   }
   return 0;
}
