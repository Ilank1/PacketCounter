#!/usr/bin/env python
from mpi4py import MPI
import numpy




comm = MPI.COMM_WORLD
rank = comm.Get_rank()

data = {'a': 7, 'b': 3.14}
req = comm.isend(data, dest=1, tag=11)
req.wait()