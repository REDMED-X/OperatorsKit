@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc deltaskscheduler.c
move /y deltaskscheduler.obj deltaskscheduler.o

