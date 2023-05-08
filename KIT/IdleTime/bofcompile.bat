@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc idletime.c
move /y idletime.obj idletime.o


