# Step 1: Install Python 3 (latest version)
Write-Host "Checking if Python 3 is installed..."
if (-Not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python not found. Installing Python 3..."
    $pythonInstallerUrl = "https://www.python.org/ftp/python/$(Invoke-RestMethod -Uri https://www.python.org/ftp/python/ | Select-String -Pattern '([0-9]+\.[0-9]+\.[0-9]+)')/python-$(Invoke-RestMethod -Uri https://www.python.org/ftp/python/ | Select-String -Pattern '([0-9]+\.[0-9]+\.[0-9]+)').exe"
    $pythonInstallerPath = "$env:TEMP\python-installer.exe"

    Invoke-WebRequest -Uri $pythonInstallerUrl -OutFile $pythonInstallerPath

    Start-Process -FilePath $pythonInstallerPath -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1" -Wait

    # Check Python installation
    $pythonVersion = python --version
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Python installation failed."
        exit 1
    }
    Write-Host "Python version installed: $pythonVersion"
} else {
    Write-Host "Python is already installed."
}

# Step 2: Install virtualenv
Write-Host "Checking if virtualenv is installed..."
if (-Not (python -m pip show virtualenv)) {
    Write-Host "virtualenv not found. Installing virtualenv..."
    python -m pip install --upgrade pip
    python -m pip install virtualenv
} else {
    Write-Host "virtualenv is already installed."
}

# Step 3: Create a virtual environment in ./backend
Write-Host "Creating virtual environment in .\backend..."
$backendPath = ".\backend"
if (-Not (Test-Path -Path $backendPath)) {
    New-Item -ItemType Directory -Force -Path $backendPath
}

if (-Not (Test-Path "$backendPath\venv\Scripts\Activate")) {
    python -m virtualenv $backendPath\venv
} else {
    Write-Host "Virtual environment already exists in $backendPath."
}

# Activate the virtual environment
Write-Host "Activating virtual environment..."
$activateScript = "$backendPath\venv\Scripts\Activate"
. $activateScript

# Step 4: Install the required libraries from requirements.txt
Write-Host "Installing required libraries from requirements.txt..."
$requirementsFile = "./backend/requirements.txt"
if (Test-Path -Path $requirementsFile) {
    pip install -r $requirementsFile
} else {
    Write-Host "No requirements.txt found, skipping..."
}

# Exit the virtual environment
Write-Host "Exiting virtual environment..."
$deactivateScript = "$backendPath\venv\Scripts\deactivate"
. $deactivateScript


# Step 5: Install MSYS2
function Find-Msys2Path {
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -ne $null }

    foreach ($drive in $drives) {
        try {
            $results = Get-ChildItem -Path $drive.Root -Directory -Recurse -Depth 4 -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Name -ieq "msys64" -and (Test-Path "$($_.FullName)\mingw64")
                }

            if ($results.Count -gt 0) {
                return $results[0].FullName
            }
        } catch {
            # Ignore errors like access denied
        }
    }

    return $null
}

$msys2Path = Find-Msys2Path

Write-Host "Checking if MSYS2 is installed..."
if (-Not $msys2Path) {
    Write-Host "MSYS2 not found. Installing MSYS2..."
    $msys2InstallerUrl = "https://repo.msys2.org/distrib/x86_64/msys2-x86_64-20250221.exe"
    $msys2InstallerPath = "$env:TEMP\msys2-installer.exe"

    Invoke-WebRequest -Uri $msys2InstallerUrl -OutFile $msys2InstallerPath

    Start-Process -FilePath $msys2InstallerPath -ArgumentList "/S" -Wait

    Start-Process -FilePath "$pacmanPath" -ArgumentList "-Syuu", "--noconfirm" -Wait
} else {
    Write-Host "MSYS2 is already installed."
}

# Step 6: Check if MSYS2 bin path in the user PATH
$msys2Path = Find-Msys2Path

# Ask user if not found
if (-not $msys2Path) {
    Write-Warning "Could not find a valid msys64 installation with mingw64 subfolder."
    $msys2Path = Read-Host "Please enter your MSYS2 installation path (e.g. D:\Tools\msys64)"
    
    # Validate input
    while (-not (Test-Path "$msys2Path\mingw64")) {
        Write-Warning "Invalid path. mingw64 folder not found inside the specified directory."
        $msys2Path = Read-Host "Please enter a valid MSYS2 installation path"
    }
}

# Add to PATH if not already included
$currentPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)

if ($currentPath -notlike "*$msys2Path*") {
    $mingwPath = "$msys2Path\mingw64\bin"
    $newPath = "$currentPath;$msys2Path;$mingwPath"

    [System.Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    $env:Path = $newPath

    Write-Output "MSYS2 path has been added to the PATH for the user and the current session."
} else {
    Write-Output "MSYS2 path is already in the PATH."
}


# Step 7: Install mingw-w64 gcc compiler in MSYS2
function Find-PacmanPath {
    param (
        [Parameter(Mandatory = $true)]
        [string]$msys2Path
    )

    try {
        $results = Get-ChildItem -Path $msys2Path -Recurse -Depth 4 -Filter "pacman.exe" -File -ErrorAction SilentlyContinue

        if ($results.Count -gt 0) {
            return $results[0].FullName
        }
    } catch {
        Write-Warning "Error occurred while searching for pacman.exe: $_"
    }

    return $null
}

$pacmanPath = Find-PacmanPath -msys2Path $msys2Path

if (-not $pacmanPath) {
    Write-Host "pacman.exe path not found under $msys2Path. Exiting..."
    return
}

Write-Host "Found pacman.exe at: $pacmanPath"

Write-Host "Checking if mingw-w64-ucrt-x86_64-gcc is installed..."
$mingwCheckCommand = Start-Process -FilePath "$pacmanPath" -ArgumentList "-Q", "mingw-w64-ucrt-x86_64-gcc" -NoNewWindow -Wait -PassThru
if ($mingwCheckCommand.ExitCode -ne 0) {
    Write-Host "Installing mingw-w64-ucrt-x86_64-gcc..."
    Start-Process -FilePath "$pacmanPath" -ArgumentList "-Sy", "mingw-w64-ucrt-x86_64-gcc --noconfirm" -Wait
} else {
    Write-Host "mingw-w64-ucrt-x86_64-gcc is already installed."
}

# Step 8: Install mingw-w64 toolchain in MSYS2
Write-Host "Checking if mingw-w64-x86_64-toolchain is installed..."
$mingwCheckCommand = Start-Process -FilePath "$pacmanPath" -ArgumentList "-Q", "mingw-w64-x86_64-toolchain" -NoNewWindow -Wait -PassThru
if ($mingwCheckCommand.ExitCode -ne 0) {
    Write-Host "Installing mingw-w64-x86_64-toolchain..."
    Start-Process -FilePath "$pacmanPath" -ArgumentList "-Sy", "mingw-w64-x86_64-toolchain --noconfirm" -Wait
} else {
    Write-Host "mingw-w64-x86_64-toolchain is already installed."
}

# Step 9: Install make in MSYS2
Write-Host "Checking if make is installed..."
$mingwCheckCommand = Start-Process -FilePath "$pacmanPath" -ArgumentList "-Q", "make" -NoNewWindow -Wait -PassThru
if ($mingwCheckCommand.ExitCode -ne 0) {
    Write-Host "Installing make..."
    Start-Process -FilePath "$pacmanPath" -ArgumentList "-Sy", "make --noconfirm" -Wait
} else {
    Write-Host "make is already installed."
}

# Step 9: Install nasm in MSYS2
Write-Host "Checking if nasm is installed..."
$mingwCheckCommand = Start-Process -FilePath "$pacmanPath" -ArgumentList "-Q", "mingw-w64-x86_64-nasm" -NoNewWindow -Wait -PassThru
if ($mingwCheckCommand.ExitCode -ne 0) {
    Write-Host "Installing nasm..."
    Start-Process -FilePath "$pacmanPath" -ArgumentList "-Sy", "mingw-w64-x86_64-nasm --noconfirm" -Wait
} else {
    Write-Host "nasm is already installed."
}

Write-Host "Setup completed successfully!"
Write-Host ""
Write-Host "[ ATTENTION ] Restart your IDE or console to apply PATH changes..." -ForegroundColor Red
