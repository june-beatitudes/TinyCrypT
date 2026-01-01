CC ?= gcc
AR ?= ar
INCLUDE_PATH := .
SOURCE_FILES := $(wildcard tinycrypt/*.c)
SOURCE_OBJECTS := $(SOURCE_FILES:tinycrypt/%.c=lib/%.o)
TEST_SOURCE_FILES := tinycrypt/tests/*.c
COMPILER_OPTS := -ffreestanding -std=c99
OPTIMIZE_LEVEL := -O3

test-main: $(SOURCE_OBJECTS) $(TEST_SOURCE_FILES)
	@ $(CC) -o test-main -O3 -I$(INCLUDE_PATH) $(SOURCE_OBJECTS) $(TEST_SOURCE_FILES)

tests: test-main
	@ ./test-main

memcheck: test-main
	@ valgrind ./test-main

lib/%.o: tinycrypt/%.c
	@ $(CC) -c $(COMPILER_OPTS) $(OPTIMIZE_LEVEL) -I$(INCLUDE_PATH) $< -o $@

lib: $(SOURCE_OBJECTS)
	@ $(AR) rcs lib/libtinycrypt.a lib/*.o

clean:
	@- rm lib/*.o test-main