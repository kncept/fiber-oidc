FROM docker.io/ubuntu:23.04
# https://github.com/kncept/slog
# DEBUGGING: docker build -f .devcontainer/ubuntu.Dockerfile -t ubuntu-dev . && docker run -it ubuntu-dev bash

# consider lscr.io/linuxserver/code-server:latest

RUN apt-get update
RUN apt-get -y install sudo wget curl vim git

# Locale injector
# RUN \
    # echo LANGUAGE=en_US.UTF-8 >> /etc/environment && \
    # echo LC_ALL=en_US.UTF-8 >> /etc/environment && \
    # echo LANG=en_US.UTF-8 >> /etc/environment && \
    # echo LC_CTYPE=en_US.UTF-8 >> /etc/environment

ARG GO_SRC_FILE=go1.21.5.linux-amd64.tar.gz
RUN \
    curl -OL https://go.dev/dl/${GO_SRC_FILE} && \
    tar -C /usr/local -xvf ${GO_SRC_FILE}
ENV PATH="${PATH}:/usr/local/go/bin"
ENV GOPRIVATE=*.kncept.com,github.com/kncept-gestalt/*

# protoc
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
      protobuf-compiler

ENV GOPATH=/home/ubuntu/go
# export GOPATH=$HOME/gowork
# export GOBIN=$GOPATH/bin  # sufficiently defaulted
ENV PATH=$PATH:$GOPATH/bin
# export PATH=$PATH:$GOPATH/bin
# export GOROOT=/usr/local/go
ENV GOROOT=/usr/local/go

# User
RUN usermod -aG sudo ubuntu
RUN echo "ubuntu:ubuntu" | chpasswd
USER ubuntu
WORKDIR /home/ubuntu

# Golang github 'insteadof' thingy
RUN \
    echo "[url \"ssh://git@github.com/\"]" >> .gitconfig && \
    echo "        insteadOf = https://github.com/" >> .gitconfig
# Golang gopls tool
RUN go install golang.org/x/tools/gopls@latest
