pip install -r requirements.txt
sudo apt-get install -y mongodb-org
sudo systemctl start mongod
chmod +x smartthings.py
export PATH=$PATH:$(pwd)