@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc silencesysmon.c
move /y silencesysmon.obj silencesysmon.o
dumpbin /disasm silencesysmon.o > silencesysmon.disasm

