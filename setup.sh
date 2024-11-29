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
# pyenv install 2.7.18
pyenv install 3.12.7

# Create virtualenvs for tools on each version
# pyenv virtualenv 2.7.18 python2-tools
pyenv virtualenv 3.12.7 python3-tools

# Install python 2 dependencies
# pyenv activate python2-tools
# pip install -r requirements-python2.txt
# source deactivate

# Install python 3 dependencies
pyenv activate python3-tools
pip install -r requirements.txt
source deactivate

# Install docker to run in user mode
curl -fsSL https://get.docker.com | sudo bash
# sudo usermod -aG docker $USER --> to run with root docker
sudo systemctl disable --now docker.service docker.socket
dockerd-rootless-setuptool.sh check --force | awk '/########## BEGIN ##########/{flag=1; next} /########## END ##########/{flag=0} flag' | bash
dockerd-rootless-setuptool.sh install --force

# Download yara rules
wget https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip
unzip yara-forge-rules-full.zip
mv packages/full/*.yar .
rm -r yara-forge-rules-full.zip packages/

# Clone repositories
git clone https://github.com/volatilityfoundation/volatility3 tools/volatility3
git clone https://github.com/horsicq/Detect-It-Easy tools/Detect-It-Easy

# Clone Volatility3 plugins
git clone https://github.com/reverseame/modex tools/modex
git clone https://github.com/f-block/volatility-plugins tools/volatility-plugins
git clone https://github.com/orchechik/check_spoof tools/check_spoof

# Copy modules to Volatility folder
cp tools/modex/*.py tools/volatility3/volatility3/framework/plugins/windows/.
cp tools/check_spoof/*.py tools/volatility3/volatility3/framework/plugins/windows/.
cp tools/volatility-plugins/*.py tools/volatility3/volatility3/framework/plugins/windows/.

# Apply fixes for modules
cp patches/*.py tools/volatility3/volatility3/framework/plugins/windows/.

# Build DIE docker image
docker build tools/Detect-It-Easy/. -t horsicq:diec

# Install CAPA from latest release
CAPA_VERSION=$(curl 'https://api.github.com/repos/mandiant/capa/releases/latest' | jq -r .tag_name)
wget https://github.com/mandiant/capa/releases/download/$CAPA_VERSION/capa-$CAPA_VERSION-linux.zip
unzip capa-$CAPA_VERSION-linux.zip
mv capa tools/capa
rm capa-$CAPA_VERSION-linux.zip