# Invoke from anywhere with make -C .../linux-v3. No production build changes.
HERE := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
WORK := $(abspath $(HERE)/../../../../..)
OUT := $(WORK)/qemu-memtrace/build/contrib/plugins
CC ?= cc
CXX ?= c++
CFLAGS := -O2 -g -Wall -Wextra -Werror -fno-pie -no-pie
CXXFLAGS := -O2 -g -std=c++17 -Wall -Wextra -Werror -Wno-missing-field-initializers
all: $(OUT)/memtrace-linux-v3 $(OUT)/verify-linux-v3
$(OUT):
	mkdir -p $@
$(OUT)/memtrace-linux-v3: $(HERE)/linux-v3.c | $(OUT)
	$(CC) $(CFLAGS) -static $< -o $@
$(OUT)/verify-linux-v3: $(HERE)/verify-linux-v3.cpp $(WORK)/traces/trace-codec/decoder.hpp $(WORK)/traces/trace-codec/wire.h $(WORK)/traces/trace_stream.hpp $(WORK)/traces/trace_csv.hpp $(WORK)/qemu-memtrace/target/i386/plugin-paging.h $(WORK)/qemu-memtrace/include/qemu/qemu-plugin.h | $(OUT)
	$(CXX) $(CXXFLAGS) -I$(WORK) -I$(WORK)/qemu-memtrace/include $< -o $@ -llzma
$(OUT)/linux-v3-fixture: $(HERE)/fixture.cpp $(WORK)/traces/trace-codec/wire.h | $(OUT)
	$(CXX) $(CXXFLAGS) -I$(WORK) $< -o $@ -llzma
test: all $(OUT)/linux-v3-fixture
	python3 $(HERE)/test-local.py
.PHONY: all test
