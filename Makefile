# Project file names
PROJECT  = pcaps

DEPS     = dgets hexString
INC      = -I..\WpdPack\Include
LIBS     = -L..\WpdPack\Lib\x64 -lwpcap
DEF      = -DADDRS
# -DDEBUG

##########

CBASE    = $(PROJECT)
ifdef DEF
DEPS    += getaddrs rewrite
LIBS    += -liphlpapi -lws2_32
endif

  # C
CDIR     = 
CADDINC  = $(INC)
CADDDEFS = $(DEF)
CADDOPTS = -fexpensive-optimizations -O3 
CADDLIBS = -s $(LIBS)

# Shouldn't need to edit these values
DEPS_O  := $(foreach dep, $(DEPS), $(dep).o)
DIST     = $(PROJECT).zip
MANIFEST = MANIFEST

##########

# Compilers
CC       = gcc.exe
CXX      = g++.exe
WINDRES  = windres.exe
DLLWRAP  = dllwrap.exe

# Utilities
CHDIR    = cd
MKDIR    = mkdir
MOVE     = cmd /c move /y
RM       = del /q
RMDIR    = rmdir
RMDIR_SQ = $(RMDIR) /s/q
  # May not be available
ZIP      = zip -r

# Compiler flags/includes
CINCS    = -I"include" $(CADDINC) 
CFLAGS   = $(CINCS) $(CADDDEFS) -Wall $(CADDOPTS) 

# C compile files
CBIN     = $(PROJECT).exe
CRES     = $(CDIR)$(PROJECT)_private.res
COBJ     = $(DEPS_O) $(CDIR)$(CBASE).o $(CRES)
CLINKOBJ = $(DEPS_O) $(CDIR)$(CBASE).o $(CRES)
CLIBS    = -L"lib" $(CADDLIBS)

# Targets
ifdef CBASE
ALL += $(CBIN)
endif

all: $(ALL)

.PHONY: all clean realclean distclean dist manifest

##########
# C .EXE
ifdef CBASE
$(CBIN): $(CLINKOBJ)
	$(CC) $(CLINKOBJ) -o $(CBIN) $(CLIBS)

$(CDIR)$(CBASE).o: $(CDIR)$(CBASE).c
	$(CC) -c $(CDIR)$(CBASE).c -o $(CDIR)$(CBASE).o $(CFLAGS)

$(CDIR)%.o: $(CDIR)%.c
	$(CC) -c $< -o $@ $(CFLAGS)

$(CDIR)$(PROJECT)_private.res: $(PROJECT)_private.rc
	$(WINDRES) -i $(PROJECT)_private.rc --input-format=rc -o $(CDIR)$(PROJECT)_private.res -O coff 
endif

##########
# Clean
clean:
	$(RM) $(COBJ) $(CXXOBJ) $(DLLCOBJ) $(DLLCXXOBJ) $(LEXOBJ) $(YACCOBJ) $(CBIN) $(CXXBIN) $(DLLCBIN) $(DLLCXXBIN) $(DLLCDEFFILE) $(DLLCSTATICLIB) $(DLLCXXDEFFILE) $(DLLCXXSTATICLIB) *.layout *.tab.* *.yy.*

distclean:
	@if exist "$(PROJECT)" $(RMDIR_SQ) "$(PROJECT)"
	@if exist "$(DIST)" $(RM) "$(DIST)"

realclean: clean distclean

##########
# Distribution
dist: distclean manifest
	$(MKDIR) "$(PROJECT)"
	@(for /f "tokens=*" %%i in ('dir /s/b/ad ^| findstr /v /e $(PROJECT)') do \
	  set MAKE_DIST_DIR=%%i&& $(MKDIR) "$(PROJECT)\!MAKE_DIST_DIR:%CD%\=!") & \
	  if not ERRORLEVEL 0 exit 0
	@for /f "tokens=*" %%i in ($(MANIFEST)) do \
	  copy "%%i" "$(PROJECT)\%%i" > nul
	$(ZIP) "$(DIST)" "$(PROJECT)"
	$(RMDIR_SQ) "$(PROJECT)"

manifest:
	@if not exist $(MANIFEST) ( \
	  @(for /f "tokens=*" %%i in ('dir /s/b/a-d') do ( \
	    setlocal ENABLEDELAYEDEXPANSION && set MANIFEST_FILE=%%i&& echo !MANIFEST_FILE:%CD%\=!>>$(MANIFEST) \
	  )) && \
	  @echo MANIFEST>>$(MANIFEST) && \
	  @sort $(MANIFEST) > $(MANIFEST).tmp && \
	  @$(MOVE) $(MANIFEST).tmp $(MANIFEST) \
	)
