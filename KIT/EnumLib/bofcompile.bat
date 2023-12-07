@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc enumlib.c
move /y enumlib.obj enumlib.o

