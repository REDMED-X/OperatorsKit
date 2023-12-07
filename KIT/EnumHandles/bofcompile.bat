@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc enumhandles.c
move /y enumhandles.obj enumhandles.o

