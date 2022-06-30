FROM ubuntu:bionic
LABEL "about"="uSBS docker image"

RUN apt update
RUN apt install -y \
      python-minimal \
      python-pip \
      python-ipython \
      python-ipdb \
      git \
      binutils-arm-none-eabi \
      binutils-arm-linux-gnueabihf \
      binutils-arm-linux-gnueabi \
      binutils

RUN python2 -m pip install --upgrade pip
RUN pip install setuptools --upgrade
RUN pip install pathlib2 lief==0.8.0.post7 pwntools==4.3.1 keystone-engine==0.9.2 six==1.16.0

ENV TERM=linux
ENV TERMINFO=/etc/terminfo
WORKDIR /root
