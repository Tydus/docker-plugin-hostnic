# docker-plugin-hostnic

docker-plugin-hostnic is a docker network plugin which can bind a host nic to a container (conceptually similar to "PCI-E Passthrough" or "SR-IOV").

<img src="https://www.ipv6ready.org/imgs/IPv6_ready_logo_phase2-8bit.png" width="100" />

## QuickStart

1. Make sure you are using Docker 1.9 or later (test with 20.10.18)

2. Build docker-plugin-hostnic and run the daemon.

```bash
go build -o docker-plugin-hostnic main.go
sudo cp docker-plugin-hostnic /usr/local/sbin
sudo cp docker-plugin-hostnic.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable docker-plugin-hostnic
sudo systemctl start docker-plugin-hostnic
```

3. Create hostnic network，the subnet and gateway argument should be same as hostnic.

```bash
docker network create -d hostnic \
--subnet=192.168.1.0/24 --gateway 192.168.1.1 --ip-range 192.168.1.128/25 \
--ipv6 --subnet 2001:db8::/64 --gateway 2001:db8:0::ffff \
network1
```

4. Run a container and binding a special host nic. We use `--mac-address` argument to identify the hostnic. Please ensure that the `--ip` argument do not conflict with other container in the same network.

```bash
docker run -it --ip 192.168.1.5 --mac-address 52:54:0e:e5:00:f7 --network network1 ubuntu:22.04 bash
```

## Additional Notes:
0. It is **strongly recommended** to run it directly on host (v.s. in a container).
Otherwise, it may cause dependency problem while restarting docker daemon and make it *very slow* to reboot a server.
1. If the `--ip` argument is not passed when running container, docker will assign an ip to the container, so please pass the `--ip` argument and ensure that the ip do not conflict with other containers.
2. Network config persistent is in `/etc/docker/hostnic/config.json`.
3. If your host only have one nic, please not use this plugin. If you bind the only nic to a container, your host will lose network connectivity.
