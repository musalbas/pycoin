class Tx_SegWit(Tx):

   @classmethod
   def parse(class_, f):
       """Parse a Bitcoin transaction Tx from the file-like object f."""
       version, = parse_struct("L", f)
       marker = ord(f.read(1))
       if marker == 0:
           flag = ord(f.read(1))
           assert flag == 1, flag
       else:
           f.seek(-1, 1)
       count, = parse_struct("I", f)
       txs_in = []
       for i in range(count):
           txs_in.append(TxIn.parse(f))
       count, = parse_struct("I", f)
       txs_out = []
       for i in range(count):
           txs_out.append(TxOut.parse(f))
       if marker == 0 and flag == 1:
           witness = []
           for i in txs_in:
               witness.append([])
               count = parse_bc_int(f)
               for i in xrange(count):
                   witness[-1].append(parse_bc_string(f))
       lock_time, = parse_struct("L", f)
       tx = class_(version, txs_in, txs_out, lock_time)
       if marker == 0 and flag == 1:
           tx.witness = witness
       return tx
