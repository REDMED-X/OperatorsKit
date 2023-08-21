@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc enumtaskscheduler.c
move /y enumtaskscheduler.obj enumtaskscheduler.o

