@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc credprompt.c
move /y credprompt.obj credprompt.o


