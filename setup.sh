#!/bin/bash

# Check if running as root
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
    SUDO_EVAL=""
else
    SUDO="sudo"
    SUDO_EVAL="sudo -E"
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Parse command line arguments
SETUP_VENV=false
for arg in "$@"; do
    case $arg in
        --setup-venv)
            SETUP_VENV=true
            shift
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Usage: $0 [--setup-venv]"
            exit 1
            ;;
    esac
done

# Install Python 3 and virtualenv if not already installed
install_python() {
    echo "Checking if Python 3 and virtualenv are installed..."

    # Check if Python3 is installed
    if ! command_exists python3; then
        echo "Python 3 not found, installing..."
        if [[ -x "$(command -v apt)" ]]; then
            $SUDO apt update
            $SUDO apt install -y python3 python3-pip python3-venv
        elif [[ -x "$(command -v dnf)" ]]; then
            $SUDO dnf install -y python3 python3-pip python3-virtualenv
        elif [[ -x "$(command -v pacman)" ]]; then
            $SUDO pacman -Syu --noconfirm python python-pip python-virtualenv
        elif [[ -x "$(command -v apk)" ]]; then
            $SUDO apk add python3 py3-pip py3-virtualenv
        else
            echo "Package manager not supported. Exiting..."
            exit 1
        fi
    else
        echo "Python 3 is already installed."
    fi

    # Install virtualenv if not already installed
    if ! command_exists virtualenv; then
        echo "Installing virtualenv..."
        $SUDO_EVAL python3 -m pip install --upgrade pip
        $SUDO_EVAL python3 -m pip install virtualenv
    else
        echo "virtualenv is already installed."
    fi
}

# Create a virtual environment and install requirements from requirements.txt
setup_virtualenv() {
    if [ "$SETUP_VENV" = false ]; then
        echo "Skipping virtual environment setup (use --setup-venv to enable)"
        return 0
    fi

    echo "Setting up virtual environment in ./backend..."
    BACKEND_DIR="./backend"

    if [ ! -d "$BACKEND_DIR" ]; then
        mkdir -p "$BACKEND_DIR"
    fi

    if [ ! -d "$BACKEND_DIR/venv" ]; then
        python3 -m venv "$BACKEND_DIR/venv"
        echo "Virtual environment created."
    else
        echo "Virtual environment already exists."
    fi

    # Activate the virtual environment
    if [ -f "$BACKEND_DIR/venv/bin/activate" ]; then
        source "$BACKEND_DIR/venv/bin/activate"
        echo "Virtual environment activated."
    else
        echo "Failed to activate virtual environment."
        return 1
    fi

    echo "Installing dependencies from requirements.txt..."
    if [ -f "./backend/requirements.txt" ]; then
        pip install -r ./backend/requirements.txt
    else
        echo "No requirements.txt found, skipping..."
    fi
}

# Install mingw-w64 toolchain (only required if building cross-platform binaries)
install_mingw() {
    echo "Checking if mingw-w64 is installed..."

    if ! command_exists x86_64-w64-mingw32-gcc; then
        echo "mingw-w64 not found, installing..."
        if [[ -x "$(command -v apt)" ]]; then
            $SUDO apt update
            $SUDO apt install -y mingw-w64
        elif [[ -x "$(command -v dnf)" ]]; then
            $SUDO dnf install -y mingw-w64
        elif [[ -x "$(command -v pacman)" ]]; then
            $SUDO pacman -Syu --noconfirm mingw-w64
        elif [[ -x "$(command -v apk)" ]]; then
            $SUDO apk add mingw-w64
        else
            echo "Unsupported distribution for mingw-w64 installation."
            exit 1
        fi
    else
        echo "mingw-w64 is already installed."
    fi
}

# Install additional required packages (e.g., mingw-w64-ucrt-x86_64-gcc)
install_additional_packages() {
    echo "Checking if additional packages are installed..."

    if ! command_exists mingw-w64-ucrt-x86_64-gcc; then
        echo "mingw-w64-ucrt-x86_64-gcc not found, installing..."
        if [[ -x "$(command -v apt)" ]]; then
            $SUDO apt install -y mingw-w64-ucrt-x86_64-gcc
        elif [[ -x "$(command -v dnf)" ]]; then
            $SUDO dnf install -y mingw-w64-ucrt-x86_64-gcc
        elif [[ -x "$(command -v pacman)" ]]; then
            $SUDO pacman -Syu --noconfirm mingw-w64-ucrt-x86_64-gcc
        elif [[ -x "$(command -v apk)" ]]; then
            echo "Alpine does not support mingw-w64-ucrt-x86_64-gcc. Skipping..."
        else
            echo "Unsupported distribution for mingw-w64-ucrt-x86_64-gcc installation."
            exit 1
        fi
    else
        echo "mingw-w64-ucrt-x86_64-gcc is already installed."
    fi
}

# Main execution
main() {
    # Detect the OS type (Debian, Fedora, Arch, Alpine)
    OS=$(uname -s)

    case $OS in
        "Linux")
            echo "Linux distribution detected."

            # Read the distribution information from /etc/os-release
            if [ -f /etc/os-release ]; then
                . /etc/os-release
                DISTRO=$ID  # 'ID' contains the lowercase distribution name
            else
                echo "/etc/os-release not found. Unable to detect distribution."
                exit 1
            fi

            case $DISTRO in
                "ubuntu"|"debian"|"linuxmint"|"fedora"|"rhel"|"centos"|"arch"|"alpine")
                    install_python
                    setup_virtualenv
                    install_mingw
                    install_additional_packages
                    ;;
                *)
                    echo "Unsupported Linux distribution: $DISTRO"
                    exit 1
                    ;;
            esac
            ;;
        *)
            echo "Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

# Run the main function
main

echo "Setup completed successfully!"
