![menu](image.png)
# TorChat
TorChat bored

```
git clone https://github.com/slyxicpy/TorChat
cd TorChat
pip install -r requirements.txt
sudo systemctl start tor
python3 oni.py
```

# Creacion serverX
```
sudo nano /etc/tor/torrc
```
Agrega al final:
```
HiddenServiceDir /var/lib/tor/my_hidden_service/
HiddenServicePort 80 127.0.0.1:12345
```
Reinicia tor:
```
sudo nano systemctl restart tor
```
Obten link onion:
```
sudo cat /var/lib/tor/my_hidden_service/hostname
```
Puede modificar a su gusto, sientase libre!
