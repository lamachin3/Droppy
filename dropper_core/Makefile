# Detect OS
UNAME_S := $(shell uname 2>/dev/null)
ifeq ($(UNAME_S),Linux)
	IS_LINUX := 1
else
	IS_WINDOWS := 1
endif

# Compiler setup
ifeq ($(IS_LINUX),1)
	CROSS_PREFIX ?= x86_64-w64-mingw32-
	EXT := .exe
	MKDIR = mkdir -p
	RM = rm -rf
else
	CROSS_PREFIX :=
	EXT :=
	MKDIR = if not exist "$(1)" mkdir "$(1)"
	RM = if exist "$(1)" rmdir /s /q "$(1)"
endif

CC = $(CROSS_PREFIX)gcc
ASM = nasm
ASMFLAGS = -f win64

# Directories
OBJ_DIR = build
BIN_DIR = bin

# Source files (fill these in, or use wildcard to include all .c files)
C_SRCS = /* SOURCE_FILES */

ASM_SRCS  = /* ASM_SOURCE_FILES */

# Output binary
OUT_FILENAME ?= dropper
OUT_EXE = $(BIN_DIR)/$(OUT_FILENAME)$(EXT)

# Object files
C_OBJS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(C_SRCS))
ASM_OBJS = $(patsubst %.nasm,$(OBJ_DIR)/%.obj,$(ASM_SRCS))
OBJS = $(C_OBJS) $(ASM_OBJS)

# Compiler and linker flags
CFLAGS = -Wall -Wextra -O2 -g -Wno-implicit-function-declaration
LIBS = -lkernel32 -luser32 -lgdi32 -lwinspool -lcomdlg32 -ladvapi32 \
	   -lshell32 -lole32 -loleaut32 -luuid -lodbc32 -lodbccp32 -lbcrypt -lsetupapi
LDFLAGS = -lmingw32 -lmsvcrt

# Optional: GUI/console toggle
HIDE_CONSOLE ?= false
ifeq ($(HIDE_CONSOLE),true)
	LDFLAGS += -Wl,--subsystem,windows
else
	LDFLAGS += -Wl,--subsystem,console
endif

# Default rule
.PHONY: all
all: setup $(OUT_EXE)

# Create required directories
.PHONY: setup
setup:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(BIN_DIR)

# Build rule for executable
$(OUT_EXE): $(OBJS)
	@echo "Linking into $@"
	$(CC) $(OBJS) $(LDFLAGS) $(LIBS) -o $@

# Compile source files
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	echo "Compiling $< -> $@"
	$(CC) $(CFLAGS) -c $< -o $@

# Assemble .nasm files
$(OBJ_DIR)/%.obj: %.nasm
	@mkdir -p $(dir $@)
	@echo "Assembling $< -> $@"
	$(ASM) $(ASMFLAGS) -o $@ $<

# Clean rule
.PHONY: clean
clean:
	@echo "Cleaning up..."
	@$(RM) $(OBJ_DIR)/*.o  # Clean object files
	@$(RM) $(BIN_DIR)/*.exe  # Clean executable
	@$(RM) $(OBJ_DIR)
	@$(RM) $(BIN_DIR)
