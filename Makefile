CC ?= gcc
INCLUDE_PATH := .
SOURCE_FILES := tinycrypt/*.c
TEST_SOURCE_FILES := tinycrypt/tests/*.c

build/test-main: $(SOURCE_FILES) $(TEST_SOURCE_FILES)
	@ $(CC) -o build/test-main -I$(INCLUDE_PATH) $(SOURCE_FILES) $(TEST_SOURCE_FILES)

tests: build/test-main
	@ ./build/test-main

memcheck: build/test-main
	@ valgrind ./build/test-main