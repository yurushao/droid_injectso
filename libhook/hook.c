#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <android/log.h>

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "hook-engine", __VA_ARGS__))
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, "hook-engine", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "hook-engine", __VA_ARGS__))

/**
 * get the address of specific module
 * if FAILED, return 0 
 */
uint32_t get_module_base(pid_t pid, const char *module_path) {
    FILE *fp = NULL;
    uint32_t addr = 0;
    char *pch = NULL;
    char filename[32];
    char line[512];
    
    if ( pid < 0 ) {
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    }
    else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    if ( (fp = fopen(filename, "r")) == NULL ) {
        LOGE("open %s failed!", filename);
        return 0;
    }

    while ( fgets(line, sizeof(line), fp) ) {
        if ( strstr(line, module_path) ) {
            pch = strtok(line, "-");
            addr = strtoul(pch, NULL, 16);
            
            break;
        }
    }

    fclose(fp);

    return addr;
}

uint32_t find_got_entry_address(const char *module_path, const char *symbol_name) {
   uint32_t module_base = get_module_base(-1, module_path);
   LOGI("[+] base address of %s: %x", module_path, module_base);

   int fd = open(module_path, O_RDONLY);
   if ( fd == -1 ) {
       LOGE("[-] open %s error!", module_path);
       return 0;
   }

   Elf32_Ehdr *elf_header = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr));
   if ( read(fd, elf_header, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr) ) {
       LOGE("[-] read %s error! in %s at line %d", module_path, __FILE__, __LINE__);
       return 0;
   }

   uint32_t sh_base = elf_header->e_shoff;
   int ndx = elf_header->e_shstrndx;
   uint32_t shstr_base = sh_base + ndx * sizeof(Elf32_Shdr);
   LOGI("[+] start of section headers: %x", sh_base);
   LOGI("[+] section header string table index: %d", ndx);
   LOGI("[+] section header of section header string table offset: %x", shstr_base);

   lseek(fd, shstr_base, SEEK_SET);
   Elf32_Shdr *shstr_shdr = (Elf32_Shdr *)malloc(sizeof(Elf32_Shdr));
   if ( read(fd, shstr_shdr, sizeof(Elf32_Shdr)) != sizeof(Elf32_Shdr) ) {
       LOGE("[-] read %s error! in %s at line %d", module_path, __FILE__, __LINE__);
       return 0;
    }
    LOGI("[+] section header string table offset: %x", shstr_shdr->sh_offset);

    char *shstrtab = (char *)malloc(sizeof(char) * shstr_shdr->sh_size);
    lseek(fd, shstr_shdr->sh_offset, SEEK_SET);
    if ( read(fd, shstrtab, shstr_shdr->sh_size) != shstr_shdr->sh_size ) {
        LOGE("[-] read %s error! in %s at line %d", module_path, __FILE__, __LINE__);
        return 0;
    }

    Elf32_Shdr *shdr = (Elf32_Shdr *)malloc(sizeof(Elf32_Shdr));
    Elf32_Shdr *relplt_shdr = (Elf32_Shdr *)malloc(sizeof(Elf32_Shdr));
    Elf32_Shdr *dynsym_shdr = (Elf32_Shdr *)malloc(sizeof(Elf32_Shdr));
    Elf32_Shdr *dynstr_shdr = (Elf32_Shdr *)malloc(sizeof(Elf32_Shdr));

    lseek(fd, sh_base, SEEK_SET);
    if ( read(fd, shdr, sizeof(Elf32_Shdr)) != sizeof(Elf32_Shdr) ) {
        LOGE("[-] read %s error! in %s at line %d", module_path, __FILE__, __LINE__);
        perror("Error");
        return 0;
    }
    int i = 1;
    char *s = NULL;
    for ( ; i < elf_header->e_shnum; i++ ) {
        s = shstrtab + shdr->sh_name;
        if ( strcmp(s, ".rel.plt") == 0 )
            memcpy(relplt_shdr, shdr, sizeof(Elf32_Shdr));
        else if ( strcmp(s, ".dynsym") == 0 ) 
            memcpy(dynsym_shdr, shdr, sizeof(Elf32_Shdr));
        else if ( strcmp(s, ".dynstr") == 0 ) 
            memcpy(dynstr_shdr, shdr, sizeof(Elf32_Shdr));

        if ( read(fd, shdr, sizeof(Elf32_Shdr)) != sizeof(Elf32_Shdr) ) {
            LOGE("[-] read %s error! i = %d, in %s at line %d", module_path, i, __FILE__, __LINE__);
            return 0;
        }
    }

    LOGI("[+] offset of .rel.plt section: %x", relplt_shdr->sh_offset);
    LOGI("[+] offset of .dynsym section: %x", dynsym_shdr->sh_offset);
    LOGI("[+] offset of .dynstr section: %x", dynstr_shdr->sh_offset);

    // read dynmaic symbol string table
    char *dynstr = (char *)malloc(sizeof(char) * dynstr_shdr->sh_size);
    lseek(fd, dynstr_shdr->sh_offset, SEEK_SET);
    if ( read(fd, dynstr, dynstr_shdr->sh_size) != dynstr_shdr->sh_size ) {
        LOGE("[-] read %s error!", module_path);
        return 0;
    }

    // read dynamic symbol table
    Elf32_Sym *dynsymtab = (Elf32_Sym *)malloc(dynsym_shdr->sh_size);
    lseek(fd, dynsym_shdr->sh_offset, SEEK_SET);
    if ( read(fd, dynsymtab, dynsym_shdr->sh_size) != dynsym_shdr->sh_size ) {
        LOGE("[-] read %s error!", module_path);
        return 0;
    }

    // read each entry of relocation table
    Elf32_Rel *rel_ent = (Elf32_Rel *)malloc(sizeof(Elf32_Rel));
    lseek(fd, relplt_shdr->sh_offset, SEEK_SET);
    if ( read(fd, rel_ent, sizeof(Elf32_Rel)) != sizeof(Elf32_Rel) ) {
        LOGE("[-] read %s error!", module_path);
        return 0;
    }
    for (i = 0; i < relplt_shdr->sh_size / sizeof(Elf32_Rel); i++ ) {
        ndx = ELF32_R_SYM(rel_ent->r_info);
        if ( strcmp(dynstr + dynsymtab[ndx].st_name, symbol_name) == 0 ) {
            LOGI("[+] got entry offset of %s: %x", symbol_name, rel_ent->r_offset);
            break;
        }
        if ( read(fd, rel_ent, sizeof(Elf32_Rel)) != sizeof(Elf32_Rel) ) {
            LOGE("[-] read %s error!", module_path);
            return 0;
        }
    }

    uint32_t offset = rel_ent->r_offset;

    free(elf_header);
    free(shstr_shdr);
    free(shstrtab);
    free(shdr);
    free(relplt_shdr);
    free(dynsym_shdr);
    free(dynstr_shdr);
    free(dynstr);
    free(dynsymtab);
    free(rel_ent);

    return offset;// + module_base;
}

/**
 * replace GOT entry content of function that indicated by symbol name
 * with the address of hook_func
 * if SUCC, return original address
 * if FAILED, return NULL
 */
uint32_t do_hook(const char *module_path, uint32_t hook_func, const char *symbol_name) {

    uint32_t *entry_addr = find_got_entry_address(module_path, symbol_name);

    if (entry_addr == 0)
        return NULL;
    
    uint32_t original_addr = *entry_addr;
    
    LOGD("[+] hook_fun addr: %x", hook_func);
    LOGD("[+] got entry addr: %x", entry_addr);
    LOGD("[+] original addr: %x", *entry_addr);

    memcpy(entry_addr, &hook_func, 4);

    return original_addr;
}
