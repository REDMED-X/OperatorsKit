@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc enumactivehosts.c
move /y enumactivehosts.obj enumactivehosts.o

