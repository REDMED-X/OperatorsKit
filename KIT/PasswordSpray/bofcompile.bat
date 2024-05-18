@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc passwordspray.c
move /y passwordspray.obj passwordspray.o

