FROM	mfisherman/openmpi

USER root

RUN apk add --update \
	python3 \
	python3-dev \
	py3-pip \
	scapy \
	libpcap &&\
	pip3 install mpi4py

USER mpi