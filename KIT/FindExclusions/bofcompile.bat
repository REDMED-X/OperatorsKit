@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc findexclusions.c
move /y findexclusions.obj findexclusions.o

