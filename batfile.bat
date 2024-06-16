@echo off
setlocal

REM Path to the Documents folder
set "folderPath=%USERPROFILE%\Documents"

REM Count the number of files in the folder
set "count=0"
for /f "delims=" %%A in ('dir /a:-d /b "%folderPath%" ^| find /c /v ""') do set "count=%%A"

REM Check if the count is 105
if "%count%" == "105" (
    echo The total number of files is 105.
    echo Running the batch file successfully.
    REM Place your successful script commands here
    exit /b 0
) else (
    echo The total number of files is NOT 105. It is %count%.
    echo Failing the batch file.
    exit /b 1
)

endlocal
