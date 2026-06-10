@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc enumdllsideloading.c
move /y enumdllsideloading.obj enumdllsideloading.o

