.RECIPEPREFIX := >

NASM          ?= nasm
LD            ?= ld
NASM_VERSION  := $(word 3,$(shell $(NASM) -v 2>/dev/null))
NASM_WARNINGS := -w+all
ifneq ($(filter 3.%,$(NASM_VERSION)),)
NASM_WARNINGS += -w-reloc-rel-dword
endif
NASMFLAGS     ?= -f elf64 -g -F dwarf $(NASM_WARNINGS)
LDFLAGS       ?=

TARGET        := authtrace
CHECKSUM      := $(TARGET).sha256
BUILD_DIR     := build
SOURCE        := src/main.asm
OBJECT        := $(BUILD_DIR)/main.o
TEST_SCRIPT   := tests/test_cli.sh

.PHONY: all clean run test release

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

release: clean
>$(MAKE) NASMFLAGS='-f elf64 -O2 $(NASM_WARNINGS)' LDFLAGS='-s' $(TARGET)
>sha256sum $(TARGET) > $(CHECKSUM)

clean:
>$(RM) -r $(BUILD_DIR) $(TARGET) $(CHECKSUM)
