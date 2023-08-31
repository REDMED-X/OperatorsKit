@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc psremote.c
move /y psremote.obj psremote.o


