@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc enumdotnet.c
move /y enumdotnet.obj enumdotnet.o
