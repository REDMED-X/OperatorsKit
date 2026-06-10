@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc spn.c
move /y spn.obj spn.o

