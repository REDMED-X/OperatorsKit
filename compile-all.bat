@ECHO OFF

for /r %%i in (*.bat) do (
    if "%%i" neq "%~f0" (
        echo Running %%i
        pushd "%%~dpi"
        call "%%i"
        popd
    )
)