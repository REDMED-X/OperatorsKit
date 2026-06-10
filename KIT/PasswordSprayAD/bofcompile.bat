@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc passwordsprayad.c
move /y passwordsprayad.obj passwordsprayad.o

