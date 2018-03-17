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

#define DECLARE_INSN(nam, match, mask) op_##nam,
typedef enum {
#include "encoding.h"
} opcode_t;
#undef DECLARE_INSN

typedef struct {
  opcode_t op;
  const char *nam;
  uint32_t match, mask;
} encoding_t;

#define DECLARE_INSN(nam, match, mask) {op_##nam, #nam, match, mask},
encoding_t encodings[] = {
#include "encoding.h"
};
#undef DECLARE_INSN

typedef struct {
  uint64_t hartid, time, valid, iaddr, w_reg, rf_wdata, rf_wen, rs0, rs0_rdata, rs1, rs1_rdata, insn0;
  encoding_t *found;
} commit_t;

commit_t instrns[1<<20];

int main(int argc, char **argv)
{
  int i, j, cnt = 0;
  int checking = 0;
  char linbuf[256];
  uint64_t cpu = 0;
  uint32_t cmd = 0;
  uint32_t exc_taken = 0;
  uint64_t pc = 0;
  uint64_t addr = 0;
  uint64_t data1 = 0;
  uint64_t data2 = 0;
  uint64_t data3 = 0;
  uint64_t fpdata = 0;
  uint32_t verbosity = 0;
  uint32_t rslt = 0;
  const char *elf = getenv("SIM_ELF_FILENAME");
  FILE *fd = fopen("rocket.log","w");
  if (!elf)
    {
    fprintf(stderr, "SIM_ELF_FILENAME is not defined\n");
    exit(1);
    }
  l3riscv_init();
  
  l3riscv_mem_load_elf();
  while (fgets(linbuf, sizeof(linbuf), stdin))
    {
      commit_t *ptr = instrns+cnt;
      int args = sscanf(linbuf, "C%ld: %ld [%ld] pc=[%lx] W[r%ld=%lx][%ld] R[r%ld=%lx] R[r%ld=%lx] inst=[%lx]",
             &(ptr->hartid), &(ptr->time), &(ptr->valid),
             &(ptr->iaddr),
             &(ptr->w_reg), &(ptr->rf_wdata), &(ptr->rf_wen),
             &(ptr->rs0), &(ptr->rs0_rdata),
             &(ptr->rs1), &(ptr->rs1_rdata),
			&(ptr->insn0));
      if (args == 12)
        {
	  ptr->found = NULL;
	  for (j = 0; j < sizeof(encodings)/sizeof(*encodings); j++)
	    {
	      if ((ptr->insn0 & encodings[j].mask) == encodings[j].match)
		ptr->found = encodings+j;
	    }
	  if (ptr->found && ptr->found->op == op_ecall)
	    ptr->valid = 1;
          if (ptr->valid && (ptr->iaddr==0x80000000))
            checking = 1;
          if (checking && ptr->valid && ptr->found)
	    {
            fprintf(fd, "C%ld: %ld [%ld] pc=[%lx] W[r%ld=%lx][%ld] R[r%ld=%lx] R[r%ld=%lx] inst=[%lx] DASM(%lx) %s\n",
                    ptr->hartid, ptr->time, ptr->valid,
                    ptr->iaddr,
                    ptr->w_reg, ptr->rf_wdata, ptr->rf_wen,
                    ptr->rs0, ptr->rs0_rdata,
                    ptr->rs1, ptr->rs1_rdata,
                    ptr->insn0, ptr->insn0, ptr->found->nam);
	    cnt++;
	    }
        }
    }
  fclose(fd);
  for (i = 0; i < cnt; i++)
        {
          commit_t *ptr = instrns+i;
          cpu = ptr->hartid;
          cmd = 0;
          exc_taken = 0;
          pc = ptr->iaddr;
	  data1 = ptr->rf_wdata;
          data2 = ptr->rs0_rdata;
          data3 = ptr->insn0;
          fpdata = 0;
          verbosity = 0;
	  addr = 0;
	  switch(ptr->found->op)
	    {
	    case op_jal:
	    case op_jalr:
	      addr = ptr[1].iaddr;
	      data1 = ptr->rf_wdata;
	      break;
	    case op_uret:
	    case op_sret:
	    case op_mret:
	    case op_beq:
	    case op_bne:
	    case op_blt:
	    case op_bge:
	    case op_bltu:
	    case op_bgeu:
	      addr = ptr[1].iaddr;
	      data1 = ptr->rf_wdata;
	      break;
	    case op_csrrw:
	    case op_csrrs:
	    case op_csrrwi:
	      addr = ptr->insn0 >> 20;
	      switch(addr)
		{
		case CSR_MISA:
		  data1 = (ptr->rf_wdata | (1<<20)) & ~0xFF;
		  break;
		case CSR_MTVEC:
		  data1 = 0x100;
		  break;
		case CSR_MSTATUS:
		  data1 = 0x2000;
		  break;
		case CSR_MEPC:
		  data1 = 0x0;
		  break;
		default:
		  data1 = ptr->rf_wdata;
		}
	      break;
	    case op_ecall:
	      data1 = ptr->rf_wdata;
	      addr = ptr[1].iaddr;
	      exc_taken = 1;
	      break;
	    case op_sw:
	      data1 = ptr->rs0_rdata;
	      data2 = ptr->rs1_rdata;
	      addr = ptr->rf_wdata;
	      break;
	    default:
	      break;
	    }
          
	  printf("op = %s(%d)\n", ptr->found->nam, ptr->found->op);
	  
          rslt = l3riscv_verify(cpu,
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
  l3riscv_done();
}
