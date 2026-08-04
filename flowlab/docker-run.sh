#!/bin/bash

docker build -t flowlab .
docker rm -f flowlab 2>/dev/null || true
docker volume rm flowlab-shared 2>/dev/null || true
docker run -d --name flowlab --network kind \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v flowlab-shared:/shared \
  flowlab
docker logs -f flowlab
