@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc keyloggerrawinput.c
move /y keyloggerrawinput.obj keyloggerrawinput.o

