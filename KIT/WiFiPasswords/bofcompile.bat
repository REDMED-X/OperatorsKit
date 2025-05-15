@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc wifipasswords.c
move /y wifipasswords.obj wifipasswords.o

