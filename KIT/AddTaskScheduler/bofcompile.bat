@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc addtaskscheduler.c
move /y addtaskscheduler.obj addtaskscheduler.o

