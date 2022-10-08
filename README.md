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

3. Create hostnic network with a list of candidate nics (specified by `-o niclist=eth1,eth3`).

```bash
docker network create -d hostnic \
-o niclist=eth1,eth3 \
--subnet=192.168.1.0/24 --gateway 192.168.1.1 --ip-range 192.168.1.128/25 \
--ipv6 --subnet 2001:db8::/64 --gateway 2001:db8:0::ffff \
network1
```

4. Run a container and binding an nic in the pool.

```bash
docker run -it --mac-address 52:54:0e:e5:00:f7 --network network1 ubuntu:22.04 bash
```

If the `--mac-address` argument is specified, the plugin will try to find the specific nic in the pool that matches the mac address, and fail if it's not available.

```bash
docker run -it --ip 192.168.1.135 --mac-address 52:54:0e:e5:00:f7 --network network1 ubuntu:22.04 bash
```

## Additional Notes:
0. It is **strongly recommended** to run it directly on host (v.s. in a container).
Otherwise, it may cause dependency problem while restarting docker daemon and make it *very slow* to reboot a server.
1. Network config is stored in `/etc/docker/hostnic/config.json`.
2. If your host only have one nic, please not use this plugin. If you bind the only nic to a container, your host will lose network connectivity.
