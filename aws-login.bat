@if not exist %userprofile%\.pip-install call pip-install.bat
@python "%~dp0\samlapi.py" %*
