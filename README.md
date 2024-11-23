# Instructions

1. Install and configure pyenv:

```shell
sudo apt update; sudo apt install -y build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev curl git libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev

curl https://pyenv.run | bash
echo 'export PYENV_ROOT="$HOME/.pyenv"' | tee -a ~/.bashrc ~/.profile > /dev/null
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' | tee -a ~/.bashrc ~/.profile > /dev/null
echo 'eval "$(pyenv init -)"' | tee -a ~/.bashrc ~/.profile > /dev/null
echo 'eval "$(pyenv virtualenv-init -)"' | tee -a ~/.bashrc ~/.profile > /dev/null

pyenv install 2.7.18 3.12.7

pyenv virtualenv 2.7.18 python2-tools
pyenv virtualenv 3.12.7 python3-tools
```

2. Install tools

Volatility3

```shell
pyenv virtualenv 3.12.7 python3-tools
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip install -t requirements.txt
```

3. Download yara rules

```shell
wget https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip
unzip yara-forge-rules-full.zip
mv packages/full/*.yar .
rm -r yara-forge-rules-full.zip packages/
```

4. Other tools installed

```bash
# docker
curl -fsSL https://get.docker.com | sudo bash
# sudo usermod -aG docker $USER --> to run with root docker
sudo systemctl disable --now docker.service docker.socket
dockerd-rootless-setuptool.sh check --force | awk '/########## BEGIN ##########/{flag=1; next} /########## END ##########/{flag=0} flag' | bash
dockerd-rootless-setuptool.sh install --force

# pip (python3-tools)
pip install --upgrade avclass-malicialab flare-capa flare-floss

# apt
sudo apt install -y libimage-exiftool-perl yara radare2 ssdeep
```
