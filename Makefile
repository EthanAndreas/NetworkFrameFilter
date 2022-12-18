CC ?= gcc
CFLAGS ?= -Og -Wall -Werror -g -lpcap
LDLIBS ?= -lm 

INCLUDE_DIR = ./include
TARGET = exe 
SRCDIR = src
OBJDIR = obj
BINDIR = bin

SOURCES := $(wildcard $(SRCDIR)/*.c)
INCLUDES := $(wildcard $(INCLUDE_DIR)/*.h)
OBJECTS := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

all : $(BINDIR)/$(TARGET)

.PHONY : docs
docs:
	@echo "\033[95mBuilding documentation...\033[0m"
	@doxygen ./Doxyfile > /dev/null 2>&1
	@echo "\033[92mDocumentation built!\033[0m"

$(BINDIR)/$(TARGET): $(OBJECTS)
	mkdir -p $(BINDIR)
	$(CC) -o $@ $^ $(CFLAGS) $(LDLIBS)
	@echo "\033[92mCompiled\033[0m"
$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	mkdir -p $(OBJDIR)
	$(CC) -o $@ -c $< $(CFLAGS) $(INCLUDE_PATH)

.PHONY : tests
tests:
	@echo "\033[92mCompilation...\033[0m"
	make
	@echo "\033[95mRunning tests...\033[0m"
	@./valgrind_tests.sh
	@echo "\033[95mTests ended\033[0m"

.PHONY: clean
clean:
	rm -rf obj/*.o
	rm -rf tests/obj/*.o
	rm -f $(BINDIR)/$(TARGET)
	rm -rf html
	@echo "\033[92mCleaned\033[0m"