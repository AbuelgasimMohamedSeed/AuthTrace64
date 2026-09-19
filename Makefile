NASM        ?= nasm
LD          ?= ld
NASMFLAGS   ?= -f elf64 -g -F dwarf -w+all -w-reloc-rel-dword
LDFLAGS     ?=

TARGET      := authtrace
BUILD_DIR   := build
SOURCE      := src/main.asm
OBJECT      := $(BUILD_DIR)/main.o

.PHONY: all clean run test

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(OBJECT): $(SOURCE) | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(TARGET): $(OBJECT)
	$(LD) $(LDFLAGS) -o $@ $^

run: $(TARGET)
	./$(TARGET)

test: $(TARGET)
	@output="$$(./$(TARGET))"; status=$$?; \
	if [ $$status -ne 0 ]; then \
		printf 'FAIL: authtrace exited with status %s\n' "$$status"; \
		exit 1; \
	fi; \
	if [ "$$output" != "AuthTrace64 v0.1" ]; then \
		printf 'FAIL: unexpected output: %s\n' "$$output"; \
		exit 1; \
	fi; \
	printf 'PASS: v0.1 smoke test\n'

clean:
	$(RM) -r $(BUILD_DIR) $(TARGET)