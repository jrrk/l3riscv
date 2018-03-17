#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <stdbool.h>
#include <fenv.h>
#include <math.h>
#ifdef __APPLE__
#include <float.h>     // For Mac OS X
#else
#include <values.h>    // For Linux
#endif

#define PART_OF_L3RISCV 1
#include "riscv_ffi.h"
#include "l3riscv.h"

typedef struct {
    uint64_t hartid, time, valid, iaddr, w_reg, rf_wdata, rf_wen, rs0, rs0_rdata, rs1, rs1_rdata, insn0, insn1;
} commit_t;

commit_t instrns[1<<20];

int main(int argc, char **argv)
{
  int i, cnt = 0;
  int checking = 0;
  char linbuf[256];
  const char *elf = getenv("SIM_ELF_FILENAME");
  FILE *fd = fopen("rocket.log","w");
  if (!elf)
    {
    fprintf(stderr, "SIM_ELF_FILENAME is not defined\n");
    exit(1);
    }
  l3riscv_init();
  atexit(l3riscv_done);
  
  l3riscv_mem_load_elf();
  while (fgets(linbuf, sizeof(linbuf), stdin))
    {
      commit_t *ptr = instrns+cnt;
      if (
      sscanf(linbuf, "C%ld: %ld [%ld] pc=[%lx] W[r%ld=%lx][%ld] R[r%ld=%lx] R[r%ld=%lx] inst=[%lx] DASM(%lx)",
             &(ptr->hartid), &(ptr->time), &(ptr->valid),
             &(ptr->iaddr),
             &(ptr->w_reg), &(ptr->rf_wdata), &(ptr->rf_wen),
             &(ptr->rs0), &(ptr->rs0_rdata),
             &(ptr->rs1), &(ptr->rs1_rdata),
             &(ptr->insn0), &(ptr->insn1)) == 13 && (ptr->insn0=ptr->insn1) && ptr->valid)
        {
          if (ptr->iaddr==0x80000000)
            checking = 1;
          cnt += checking;
          if (checking)
            fprintf(fd, "C%ld: %ld [%ld] pc=[%lx] W[r%ld=%lx][%ld] R[r%ld=%lx] R[r%ld=%lx] inst=[%lx] DASM(%lx)\n",
                    ptr->hartid, ptr->time, ptr->valid,
                    ptr->iaddr,
                    ptr->w_reg, ptr->rf_wdata, ptr->rf_wen,
                    ptr->rs0, ptr->rs0_rdata,
                    ptr->rs1, ptr->rs1_rdata,
                    ptr->insn0, ptr->insn1);
        }
    }
  fclose(fd);
  for (i = 0; i < cnt; i++)
        {
          commit_t *ptr = instrns+i;
          uint64_t cpu = ptr->hartid;
          uint32_t cmd = 0;
          uint32_t exc_taken = 0;
          uint64_t pc = ptr->iaddr;
          uint64_t addr = ptr[1].iaddr;
          uint64_t data1 = ptr->rf_wdata;
          uint64_t data2 = ptr->rs0_rdata;
          uint64_t data3 = ptr->rs1_rdata;
          uint64_t fpdata = 0;
          uint32_t verbosity = 0;
          uint32_t rslt = l3riscv_verify(cpu,
                                         cmd,
                                         exc_taken,
                                         pc,
                                         addr,
                                         data1,
                                         data2,
                                         data3,
                                         fpdata,
                                         verbosity);
        }
}
