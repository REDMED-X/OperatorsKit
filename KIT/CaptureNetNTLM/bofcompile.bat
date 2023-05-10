@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc capturenetntlm.c
move /y capturenetntlm.obj capturenetntlm.o


