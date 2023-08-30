@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc findfile.c
move /y findfile.obj findfile.o

