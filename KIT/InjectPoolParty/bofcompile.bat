@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc injectpoolparty.c
move /y injectpoolparty.obj injectpoolparty.o

