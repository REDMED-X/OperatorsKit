@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc hidefile.c
move /y hidefile.obj hidefile.o
dumpbin /disasm hidefile.o > hidefile.disasm

