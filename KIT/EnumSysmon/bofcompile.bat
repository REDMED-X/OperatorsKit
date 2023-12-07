@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc enumsysmon.c
move /y enumsysmon.obj enumsysmon.o

