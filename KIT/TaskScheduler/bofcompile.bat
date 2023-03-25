@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc taskscheduler.c
move /y taskscheduler.obj taskscheduler.o

