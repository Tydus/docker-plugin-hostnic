# docker-plugin-hostnic

docker-plugin-hostnic is a docker network plugin which can binding a special host nic to a container.
It is *not recommended* to run it in container since it may cause dependency problem while restart docker daemon and make restarting *very slow*.

## QuickStart

1. Make sure you are using Docker 1.9 or later (test with 20.10.18)
2. Build docker-plugin-hostnic and run.

```bash
go build -o docker-plugin-hostnic main.go
cp docker-plugin-hostnic /usr/local/sbin
(docker-plugin-hostnic &)
```

3. Create hostnic network，the subnet and gateway argument should be same as hostnic.

```bash
docker network create -d hostnic --subnet=192.168.1.0/24 --gateway 192.168.1.1 hostnic
```

4. Run a container and binding a special hostnic. We use `--mac-address` argument to identify the hostnic. Please ensure that the ip argument do not conflict with other container in the same network.

```bash
docker run -it --ip 192.168.1.5 --mac-address 52:54:0e:e5:00:f7 --network hostnic ubuntu:22.04 bash
```

## Additional Notes:

1. If the `--ip` argument is not passed when running container, docker will assign an ip to the container, so please pass the `--ip` argument and ensure that the ip do not conflict with other containers.
2. Network config persistent is in `/etc/docker/hostnic/config.json`.
3. If your host only have one nic, please not use this plugin. If you binding the only nic to container, your host will lost network connectivity.
