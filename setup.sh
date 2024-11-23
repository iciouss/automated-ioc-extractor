#!/bin/bash

# Update apt and install dev tools 
echo "Installing needed packages" 
sudo apt update; sudo apt install -y build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev curl git libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev

# Install pyenv
echo "Installing pyenv and preparing virtualenvs."
curl https://pyenv.run | bash
echo 'export PYENV_ROOT="$HOME/.pyenv"' | tee -a ~/.bashrc ~/.profile > /dev/null
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' | tee -a ~/.bashrc ~/.profile > /dev/null
echo 'eval "$(pyenv init -)"' | tee -a ~/.bashrc ~/.profile > /dev/null
echo 'eval "$(pyenv virtualenv-init -)"' | tee -a ~/.bashrc ~/.profile > /dev/null
exec "$SHELL"

# Install python 2 and python 3 
pyenv install 2.7.18 3.12.7

# Create virtualenvs for tools on each version
pyenv virtualenv 2.7.18 python2-tools
pyenv virtualenv 3.12.7 python3-tools

# Install python 2 dependencies
pyenv activate python2-tools
pip install -r requirements-python2.txt
source deactivate

# Install python 3 dependencies
pyenv activate python3-tools
pip install -r requirements-python3.txt
source deactivate

# Download yara rules
wget https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip
unzip yara-forge-rules-full.zip
mv packages/full/*.yar .
rm -r yara-forge-rules-full.zip packages/

# Install docker to run in user mode
curl -fsSL https://get.docker.com | sudo bash
# sudo usermod -aG docker $USER --> to run with root docker
sudo systemctl disable --now docker.service docker.socket
dockerd-rootless-setuptool.sh check --force | awk '/########## BEGIN ##########/{flag=1; next} /########## END ##########/{flag=0} flag' | bash
dockerd-rootless-setuptool.sh install --force