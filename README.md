# CS395T Learning Based ZRAM

### Installing BCC
sudo apt-get update
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)

### Connect SSH to Github
ssh-keygen -t ed25519 -C "your_email@example.com"

eval "$(ssh-agent -s)"

ssh-add ~/.ssh/id_ed25519

cat ~/.ssh/id_ed25519.pub

add public key to github

### Enable ZRAM
sudo modprobe zram
https://fosspost.org/enable-zram-on-linux-better-system-performance

sudo cat /proc/kallsyms | grep zram
sudo sysctl vm.swappiness=80
watch -n 1 cat /proc/swaps
stress-ng --vm 2 --vm-bytes 120% --timeout 60s
free -h


### Run BCC Script
chmod +x script_name.py
sudo ./script_name.py
