CXX ?= g++
MCL_DIR ?= /usr/local
CXXFLAGS ?= -O2 -DNDEBUG -std=c++17 -Wall -Wextra -Wpedantic
CXXFLAGS += -DMCL_FP_BIT=384 -DMCL_FR_BIT=256
CPPFLAGS += -I$(MCL_DIR)/include
LDLIBS ?= -lgmpxx -lgmp -pthread
TARGET = paews_mcl_bench

all: $(TARGET)

# Links mcl statically, as in the reported measurements.
$(TARGET): paews_mcl_bench.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $< $(MCL_DIR)/lib/libmcl.a $(LDLIBS) -o $@

quick: $(TARGET)
	./$(TARGET) --runs 100 --validate 10 --warmup 5 --pool 4 --csv quick.csv

# Same settings as results/ (10,000 timed samples and 10,000 independent validations).
bench: $(TARGET)
	./$(TARGET) --n 8 --runs 10000 --validate 10000 --warmup 50 --pool 16 \
	  --csv paews_bls12_381_validate10000.csv | tee paews_run_validate10000.log

clean:
	rm -f $(TARGET) quick.csv paews_bls12_381_validate10000.csv paews_run_validate10000.log paews_environment.txt

.PHONY: all quick bench clean
