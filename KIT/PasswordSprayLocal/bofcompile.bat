@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc passwordspraylocal.c
move /y passwordspraylocal.obj passwordspraylocal.o

