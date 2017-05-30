@echo off
@echo Compiling Client
cd client
make
cd ..

@echo Compiling Server
cd server
make
cd ..

@echo Compiled
