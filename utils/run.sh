docker-machine create --driver digitalocean --digitalocean-access-token $DO_TOKEN --digitalocean-size s-1vcpu-2gb-amd --digitalocean-image ubuntu-20-04-x64  --digitalocean-region sgp1  --engine-install-url "https://releases.rancher.com/install-docker/19.03.9.sh" mydocker

