# Installation Instructions

## 1. (Optional) Set up a virtual environment

Create and activate a virtual environment to isolate dependencies:

python3 -m venv venv

Activate it:

- Linux or macOS:
  source venv/bin/activate
  
- Windows:
  venv\Scripts\activate

Then install Python packages:

pip install -r requirements.txt

## 2. (Mandatory) Install required Python packages 

Ensure pip is installed, then run:

pip install -r requirements.txt

## 3. (Mandatory)  Install OpenSSL (for TLS support)

- Linux (Debian/Ubuntu):
  sudo apt install openssl
  
- macOS (requires Homebrew):
  brew install openssl
  
- Windows: 
  Download and install manually from https://slproweb.com/products/Win32OpenSSL.html

## 4. (Mandatory)  Install Nmap (to use Ncat for secure connections)

- Linux (Debian/Ubuntu):
  sudo apt install nmap
  
- macOS (requires Homebrew):
  brew install nmap
  
- Windows: 
  Download and install manually from https://nmap.org/ (Ncat is included)
  
## 5. (Mandatory) Start the program

Run the main Python file:

python3 __init__.py

or (on Windows if python3 does not work):

python __init__.py

## 6. (Mandatory) Connect to the TLS server on port 9999

### Using Ncat

- Linux or macOS:
  ncat --ssl 127.0.0.1 9999
  
- Windows:
  ncat.exe --ssl 127.0.0.1 9999

### Using OpenSSL

(all systems):

openssl s_client -connect 127.0.0.1:9999


