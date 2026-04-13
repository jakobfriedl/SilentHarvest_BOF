PROJECT = silentharvest

CCX64  := x86_64-w64-mingw32-gcc
CCX86  := i686-w64-mingw32-gcc
CFLAGS := -Wall -Werror -Os -s -Iinclude -D_NO_NTDLL_CRT_

# BOFPatcher
OCPY   := objcopy
IMPORTS86 := include/imports_$(PROJECT)86.txt
IMPORTS64 := include/imports_$(PROJECT)64.txt

.DEFAULT: all
.PHONY: all
all: bof

.PHONY: bof
bof: $(PROJECT).x64.o $(PROJECT).x86.o

$(PROJECT).x64.o: src/main.c
	$(CCX64) -c $< -o dist/$@ $(CFLAGS)
	@$(OCPY) --redefine-syms=$(IMPORTS64) dist/$@ dist/$@

$(PROJECT).x86.o: src/main.c
	$(CCX86) -c $< -o dist/$@ $(CFLAGS)
	@$(OCPY) --redefine-syms=$(IMPORTS86) dist/$@ dist/$@
	
.PHONY: clean
clean:
	rm -f dist/$(PROJECT)*.x64.o
	rm -f dist/$(PROJECT)*.x86.o
