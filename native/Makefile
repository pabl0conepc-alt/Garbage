CC ?= cc
CXX ?= c++
CARGO ?= cargo
BUILD ?= build
CFLAGS ?= -O2 -fPIC -Wall -Wextra -Wpedantic -std=c11
CXXFLAGS ?= -O2 -fPIC -Wall -Wextra -Wpedantic -std=c++17
INCLUDES := -Iinclude

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
SHARED_C := -dynamiclib
SHARED_CXX := -dynamiclib
LIB_C := $(BUILD)/libgarbage_c.dylib
LIB_CPP := $(BUILD)/libgarbage_cpp.dylib
RUST_SOURCE := rust/target/release/libgarbage_native_rust.dylib
LIB_RUST := $(BUILD)/libgarbage_rust.dylib
else
SHARED_C := -shared
SHARED_CXX := -shared
LIB_C := $(BUILD)/libgarbage_c.so
LIB_CPP := $(BUILD)/libgarbage_cpp.so
RUST_SOURCE := rust/target/release/libgarbage_native_rust.so
LIB_RUST := $(BUILD)/libgarbage_rust.so
endif

.PHONY: all c cpp rust check clean

all: c cpp rust

$(BUILD):
	mkdir -p $(BUILD)

c: $(LIB_C)

C_SOURCES := c/garbage_native.c c/garbage_fuzzy.c

$(LIB_C): $(C_SOURCES) include/garbage_native.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) $(SHARED_C) -o $@ $(C_SOURCES) -lm

cpp: $(LIB_CPP)

$(LIB_CPP): cpp/garbage_graph.cpp include/garbage_graph.h | $(BUILD)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SHARED_CXX) -o $@ cpp/garbage_graph.cpp

rust: $(LIB_RUST)

$(LIB_RUST): rust/src/lib.rs rust/Cargo.toml | $(BUILD)
	cd rust && $(CARGO) build --release
	cp $(RUST_SOURCE) $@

check: all
	cd .. && GARBAGE_NATIVE_DIR="$(CURDIR)/$(BUILD)" python3 -m unittest tests.test_native

clean:
	rm -rf $(BUILD)
	cd rust && $(CARGO) clean
