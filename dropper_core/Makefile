# Compiler
CC = cl.exe

# Linker
LINKER = link.exe

# Directories
SRC_DIR = .
OBJ_DIR = build
BIN_DIR = bin

# OS
OS := $(shell uname 2>/dev/null || echo Windows)

# User-defined macros (passed as arguments)
OUT_FILENAME ?= dropper.exe

# Add binaries to PATH
RC_PATH = C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64
export PATH := $(RC_PATH);$(PATH)

# Include directories (ensure these paths are quoted)
INCLUDE_DIRS = /I"C:/Users/lamachin3/Downloads/vcpkg-master/vcpkg-master/installed/x64-windows/include" \
               /I"C:/Program Files (x86)/Windows Kits/10/include/10.0.22621.0/um" \
               /I"C:/Program Files (x86)/Windows Kits/10/include/10.0.22621.0/shared" \
               /I"C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.40.33807/include" \
               /I"C:/Program Files (x86)/Windows Kits/10/include/10.0.22621.0/ucrt" \
               /I"C:/Users/lamachin3/Projets/Droppy/dropper_core"

# Compiler flags
CFLAGS = /c /Zi /JMC /nologo /W3 /WX- /diagnostics:column /Od /D _CONSOLE /Gm- /EHsc /RTC1 /MT /GS \
         /fp:precise /Zc:wchar_t /Zc:forScope /Zc:inline /TC /FC /errorReport:queue

# Define the directories for the libraries (using the paths from the working Visual Studio command)
LIBPATH += /LIBPATH:"C:/Users/lamachin3/Downloads/vcpkg-master/vcpkg-master/installed/x64-windows/debug/lib"
LIBPATH += /LIBPATH:"C:/Users/lamachin3/Downloads/vcpkg-master/vcpkg-master/installed/x64-windows/debug/lib/manual-link"
LIBPATH += /LIBPATH:"C:/Program Files (x86)/Windows Kits/10/Lib/10.0.22621.0/um/x64"
LIBPATH += /LIBPATH:"C:/Program Files (x86)/Windows Kits/10/Lib/10.0.22621.0/ucrt/x64"
LIBPATH += /LIBPATH:"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.40.33807\lib\x64"

# Define libraries to link against
LIBS = kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib

# Linker flags
LFLAGS = /ERRORREPORT:QUEUE /OUT:"$(BIN_DIR)/$(OUT_FILENAME)" /INCREMENTAL /NOLOGO \
         $(LIBPATH) $(LIBS) /MANIFEST /MANIFESTUAC:"level='asInvoker' uiAccess='false'" /manifest:embed \
         /DEBUG /PDB:"$(BIN_DIR)/Droppy_core.pdb" /ENTRY:"main" /TLBID:1 /DYNAMICBASE /NXCOMPAT /MACHINE:X64 \
         /DEFAULTLIB:libcmt.lib /DEFAULTLIB:libucrt.lib /DEFAULTLIB:libvcruntime.lib

ifneq ($(HIDE_CONSOLE), "")
    LFLAGS += /SUBSYSTEM:WINDOWS
else
    LFLAGS += /SUBSYSTEM:CONSOLE
endif

# Source files
SRCS = /* SOURCE_FILES */

# Object files
OBJS = $(SRCS:%.c=$(OBJ_DIR)/%.obj)

# Build rules
all: setup compile link

setup:
	@if not exist "$(OBJ_DIR)" mkdir "$(OBJ_DIR)" & if not exist "$(BIN_DIR)" mkdir "$(BIN_DIR)"

compile: $(OBJS)

# Object file compilation rule
$(OBJ_DIR)/%.obj: $(SRC_DIR)/%.c
	@if not exist "$(dir $@)" mkdir "$(dir $@)"
	$(CC) $(CFLAGS) $(INCLUDE_DIRS) /Fo$@ $<

link:
	$(LINKER) $(LFLAGS) $(OBJS)

clean:
	@if exist "$(OBJ_DIR)" rmdir /S /Q "$(OBJ_DIR)"
	@if exist "$(BIN_DIR)" rmdir /S /Q "$(BIN_DIR)"
