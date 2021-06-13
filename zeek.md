wget -nv https://download.opensuse.org/repositories/security:zeek/xUbuntu_18.04/Release.key -O Release.key

apt-key add -< Release.key

echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/ /'  | sudo tee /etc/apt/sources.list.d/security:zeek.list

ehtool -K ens33 rx off tx off sg off tso off gso off gro off
