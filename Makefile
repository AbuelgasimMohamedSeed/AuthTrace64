.RECIPEPREFIX := >

NASM        ?= nasm
LD          ?= ld
NASMFLAGS   ?= -f elf64 -g -F dwarf -w+all -w-reloc-rel-dword
LDFLAGS     ?=

TARGET      := authtrace
BUILD_DIR   := build
SOURCE      := src/main.asm
OBJECT      := $(BUILD_DIR)/main.o
TEST_SCRIPT := tests/test_cli.sh

.PHONY: all clean run test

all: $(TARGET)

$(BUILD_DIR):
>mkdir -p $(BUILD_DIR)

$(OBJECT): $(SOURCE) | $(BUILD_DIR)
>$(NASM) $(NASMFLAGS) -o $@ $<

$(TARGET): $(OBJECT)
>$(LD) $(LDFLAGS) -o $@ $^

run: $(TARGET)
>@test -n "$(LOG)" || { printf 'Usage: make run LOG=path/to/auth.log\n'; exit 2; }
>./$(TARGET) "$(LOG)"

test: $(TARGET) $(TEST_SCRIPT)
>./$(TEST_SCRIPT) ./$(TARGET)

clean:
>$(RM) -r $(BUILD_DIR) $(TARGET)
