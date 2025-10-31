# escape=`

FROM mcr.microsoft.com/windows/servercore:ltsc2022

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

# Set up working directory
WORKDIR /opkssh-build

# Install and start OpenSSH Server (creates /ProgramData/ssh initial files and folders)
RUN Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 ; `
    Start-Service sshd ; `
    Start-Sleep -Seconds 2 ; `
    Stop-Service sshd

# Set Administrator password
RUN net user Administrator "P@ssw0rd123!"

# Install Chocolatey
RUN Set-ExecutionPolicy Bypass -Scope Process -Force; `
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; `
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install Go
RUN choco install -y golang --version=1.25.3

# Copy go.mod and go.sum for dependency caching
COPY go.mod go.sum ./

# Download Go modules
RUN go mod download

# Copy files
COPY . ./

# Build opkssh binary
RUN go build -v -o opkssh.exe

# Install opkssh
COPY scripts/windows/Install-OpksshServer.ps1 /temp/
RUN /temp/Install-OpksshServer.ps1 `
    -InstallFrom /opkssh-build/opkssh.exe `
    -NoSshdRestart `
    -AuthCmdUser 'opksshuser' `
    -Verbose

# Authorize GitHub provider for SSH logins
RUN Add-Content -Path '/ProgramData/opk/providers' -Value 'https://token.actions.githubusercontent.com github oidc'

# Add integration test user as allowed in policy
# ARG is used to pass build-time variables
ARG AUTHORIZED_REPOSITORY
ARG AUTHORIZED_REF

RUN $env:PATH = [System.Environment]::GetEnvironmentVariable('Path','Machine'); `
    & '/Program Files/opkssh/opkssh.exe' add Administrator "repo:${env:AUTHORIZED_REPOSITORY}:ref:${env:AUTHORIZED_REF}" https://token.actions.githubusercontent.com

# Expose SSH port
EXPOSE 22

# Start SSH service when container starts
CMD ["/Windows/System32/OpenSSH/sshd.exe", "-D"]
