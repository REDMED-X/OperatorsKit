@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc forcelockscreen.c
move /y forcelockscreen.obj forcelockscreen.o

