@echo off
setlocal

set SDK=C:\Users\posad\AppData\Local\Android\Sdk
set BT=%SDK%\build-tools\36.1.0
set PLATFORM=%SDK%\platforms\android-36.1\android.jar
set JAVA_HOME=C:\Program Files\Java\jdk-17
set JAVAC=%JAVA_HOME%\bin\javac.exe
set JAR=%JAVA_HOME%\bin\jar.exe
set KEYTOOL=%JAVA_HOME%\bin\keytool.exe
set PROJ=C:\InfoSec\android-redteam\apk

echo [1/7] Compiling resources...
"%BT%\aapt" package -f -m -J "%PROJ%\gen" -M "%PROJ%\AndroidManifest.xml" -S "%PROJ%\res" -I "%PLATFORM%" 2>&1
if errorlevel 1 (echo AAPT FAILED & exit /b 1)

echo [2/7] Compiling Java...
if not exist "%PROJ%\obj" mkdir "%PROJ%\obj"
"%JAVAC%" -source 8 -target 8 -d "%PROJ%\obj" -classpath "%PLATFORM%" -sourcepath "%PROJ%\src;%PROJ%\gen" "%PROJ%\src\com\redteam\probe\*.java" 2>&1
if errorlevel 1 (echo JAVAC FAILED & exit /b 1)

echo [3/7] Converting to DEX...
call "%BT%\d8.bat" --min-api 23 --output "%PROJ%\dex" "%PROJ%\obj\com\redteam\probe\*.class" 2>&1
if errorlevel 1 (echo D8 FAILED & exit /b 1)

echo [4/7] Packaging APK...
"%BT%\aapt" package -f -M "%PROJ%\AndroidManifest.xml" -S "%PROJ%\res" -I "%PLATFORM%" -F "%PROJ%\probe-unsigned.apk" 2>&1
if errorlevel 1 (echo AAPT2 FAILED & exit /b 1)

cd /d "%PROJ%"
"%BT%\aapt" add "%PROJ%\probe-unsigned.apk" "dex\classes.dex" 2>&1

echo [5/7] Generating signing key...
if not exist "%PROJ%\probe.keystore" (
    "%KEYTOOL%" -genkey -v -keystore "%PROJ%\probe.keystore" -keyalg RSA -keysize 2048 -validity 10000 -alias probe -storepass probepass -keypass probepass -dname "CN=Probe,OU=RedTeam,O=Test,L=Test,S=Test,C=US" 2>&1
)

echo [6/7] Signing APK...
call "%BT%\apksigner.bat" sign --ks "%PROJ%\probe.keystore" --ks-pass pass:probepass --key-pass pass:probepass --out "%PROJ%\probe.apk" "%PROJ%\probe-unsigned.apk" 2>&1
if errorlevel 1 (echo SIGN FAILED & exit /b 1)

echo [7/7] Done!
echo APK: %PROJ%\probe.apk
dir "%PROJ%\probe.apk"
