#! /usr/bin/env python3

from scapy.all import sniff
from scapy.config import conf
from scapy.all import DNS, DNSQR, IP, sr1, UDP
import subprocess, random
from collections import Counter


queries = {}

from mpi4py import MPI

comm = MPI.COMM_WORLD
rank = comm.Get_rank()

if rank == 0:
    print("Runnig mpi server on rank 0")

    for i in range(10):
        qtype = random.choice(["ns", "a"])
        process = subprocess.Popen(["nslookup", f"-type={qtype}", f"some_domain"], stdout=subprocess.PIPE)

    req = comm.irecv(source=1)
    data_from_rank_1 = req.wait()

    req = comm.irecv(source=2)
    data_from_rank_2 = req.wait()
    
    merged_queries = dict(Counter(data_from_rank_1)+Counter(data_from_rank_2))

    print(f"Merged: {merged_queries}")

else:
    print(f"Runnig counter on rank: {rank}")
    def send_telemtry(packet):
        name = None
        #print(packet.show())
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

    print(queries)
    req = comm.isend(queries, dest=0)
    req.wait()
    

