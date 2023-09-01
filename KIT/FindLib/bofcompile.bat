@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc findlib.c
move /y findlib.obj findlib.o

