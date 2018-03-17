TEST=rv64um-v-mul
L3RISCV=/local/scratch/$(USER)/l3riscv
ROCKET=/local/scratch/$(USER)/rocket-chip
RISCV=$(ROCKET)/riscv
ROCKETLOG=$(L3RISCV)/src/sml/riscv_rocketlog
export LD_LIBRARY_PATH=$(L3RISCV)
export SIM_ELF_FILENAME=$(ROCKET)/emulator/output/$(TEST)

$(ROCKETLOG): $(ROCKETLOG).c
	gcc $@.c -L../.. -ll3riscv -o $@

test: $(ROCKETLOG)
	$(ROCKETLOG) < $(SIM_ELF_FILENAME).out |& $(RISCV)/bin/spike-dasm |& tee test.log

ref:
	$(L3RISCV)/l3riscv --trace 1 $(SIM_ELF_FILENAME)

dis:
	$(L3RISCV)/l3riscv --dis true $(SIM_ELF_FILENAME)

log:
	$(RISCV)/bin/spike-dasm < rocket.log > rocket.dis
