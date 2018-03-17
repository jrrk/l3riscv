TEST=rv64ui-p-add
L3RISCV=/local/scratch/$(USER)/l3riscv
ROCKET=/local/scratch/$(USER)/freedom/rocket-chip
RISCV=$(ROCKET)/riscv
ROCKETLOG=$(L3RISCV)/src/sml/riscv_rocketlog
export LD_LIBRARY_PATH=$(L3RISCV)
SIM_ELF_TEST=$(ROCKET)/emulator/output/$(TEST)
SIM_ELF_LOG=$(SIM_ELF_TEST).out
export SIM_ELF_FILENAME=$(SIM_ELF_TEST)

$(ROCKETLOG): $(ROCKETLOG).c
	gcc -g $@.c -L../.. -ll3riscv -o $@

test: $(ROCKETLOG) $(SIM_ELF_FILENAME) $(SIM_ELF_LOG)
	$(ROCKETLOG) < $(SIM_ELF_LOG) |& $(RISCV)/bin/spike-dasm |& tee test.log

ref:
	$(L3RISCV)/l3riscv --trace 1 $(SIM_ELF_FILENAME)

dis:
	$(L3RISCV)/l3riscv --dis true $(SIM_ELF_FILENAME)

log:
	$(RISCV)/bin/spike-dasm < rocket.log > rocket.dis
