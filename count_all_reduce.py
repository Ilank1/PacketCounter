#! /usr/bin/env python3

from scapy.all import sniff
from scapy.config import conf
from scapy.all import DNS, DNSQR, IP, sr1, UDP
import subprocess, random

queries = {}

from mpi4py import MPI

comm = MPI.COMM_WORLD
rank = comm.Get_rank()


def addCounter(counter1, counter2, datatype):
    for item in counter2:
        if item in counter1:
            counter1[item] += counter2[item]
        else:
            counter1[item] = counter2[item]
    return counter1


if rank == 0 or rank == 1:
    print(f"Sending DNS queries from rank {rank}")

    for i in range(20):
        qtype = random.choice(["ns", "a"])
        process = subprocess.Popen(["nslookup", f"-type={qtype}", f"some_domain"], stdout=subprocess.PIPE)

def send_telemtry(packet):
    name = None

    if packet.haslayer(DNS):   
        
        # Filter dns a record queries with more than 1 domain(just one currently...)
        if packet.qdcount > 0 and isinstance(packet.qd, DNSQR):

            # rank 1 will count a queries
            if rank == 1 and packet.qd.qtype == 1:
                name = packet.qd.qname

            # rank 2 will count ns queries
            if rank == 2 and packet.qd.qtype == 2:
                name = packet.qd.qname

            if name is not None:
                print(f"Got query: {name}")
                if name not in queries:
                    queries[name] = 1
                else:
                    queries[name] += 1

        elif packet.ancount > 0 and isinstance(packet.an, DNSRR):
            print("Got answer {packet.an.rdata}")
        else:
            return None

# Sniffing dns packets with some limit            
sniff(filter="udp port 53", prn=send_telemtry,count=10)


print(f"Captured queries: {queries}, rank {rank}")

counterSumOp = MPI.Op.Create(addCounter, commute=True)

totDict = comm.allreduce(queries, op=counterSumOp)

print(rank, totDict)