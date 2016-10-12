import io

from pycoin.encoding import double_sha256, from_bytes_32
from pycoin.serialize import b2h
from pycoin.serialize.bitcoin_streamer import (
    parse_struct, parse_bc_int, parse_bc_string,
    stream_struct
)

from pycoin.tx import Tx, TxIn, TxOut
from pycoin.tx.script import tools


class TxSegwit(Tx):

    @classmethod
    def parse(class_, f):
        """Parse a Bitcoin transaction Tx from the file-like object f."""
        txs_in = []
        txs_out = []
        version, = parse_struct("L", f)
        is_segwit = False
        v = ord(f.read(1))
        is_segwit = (v == 0)
        if is_segwit:
            flag = f.read(1)
            if flag != b'\1':
                raise ValueError("bad flag in segwit")
            v = None
        count = parse_bc_int(f, v=v)
        txs_in = []
        for i in range(count):
            txs_in.append(TxIn.parse(f))
        count = parse_bc_int(f)
        txs_out = []
        for i in range(count):
            txs_out.append(TxOut.parse(f))

        witnesses = []
        if is_segwit:
            for i in txs_in:
                stack = []
                count = parse_bc_int(f)
                for i in range(count):
                    stack.append(parse_bc_string(f))
                witnesses.append(stack)
        lock_time, = parse_struct("L", f)
        tx = class_(version, txs_in, txs_out, lock_time)
        tx.witnesses = witnesses
        return tx

    def stream1(self, f, blank_solutions=False, include_unspents=False):
        is_segwit = len(self.witnesses) > 0
        stream_struct("L", f, self.version)
        if is_segwit:
            f.write(b'\0\1')
        stream_struct("I", f, len(self.txs_in))
        for t in self.txs_in:
            t.stream(f, blank_solutions=blank_solutions)
        stream_struct("I", f, len(self.txs_out))
        for t in self.txs_out:
            t.stream(f)
        stream_struct("L", f, self.lock_time)
        if is_segwit:
            for witness in self.witnesses:
                stream_struct(f, "[S]", witness)
        if include_unspents and not self.missing_unspents():
            self.stream_unspents(f)

    def set_witnesses(self, witnesses):
        assert len(witnesses) == len(self.txs_in)
        for w in witnesses:
            assert isinstance(w, bytes)
        self.witnesses = witnesses

    def w_hash(self):
        pass

    def w_id(self):
        return b2h(self.w_hash())

    def verify_tx_in(self, tx_in_idx, tx_out_script, expected_hash_type=None):
        tx_in = self.txs_in[tx_in_idx]

        def signature_for_hash_type_f(hash_type, script):
            return self.signature_hash(script, tx_in_idx, hash_type)

        witness = None
        if self.witnesses:
            import pdb; pdb.set_trace()
            witness = self.witness[tx_in_idx]
        if not tx_in.verify(
                tx_out_script, signature_for_hash_type_f, expected_hash_type, witness=witness):
            raise ValidationFailureError(
                "just signed script Tx %s TxIn index %d did not verify" % (
                    b2h_rev(tx_in.previous_hash), tx_in_idx))

    def hash_prevouts(self):
        f = io.BytesIO()
        for tx_in in self.txs_in:
            f.write(tx_in.previous_hash)
            stream_struct("L", f, tx_in.previous_index)
        return double_sha256(f.getvalue())

    def hash_sequence(self):
        f = io.BytesIO()
        for tx_in in self.txs_in:
            stream_struct("L", f, tx_in.sequence)
        return double_sha256(f.getvalue())

    def hash_outputs(self):
        f = io.BytesIO()
        for tx_out in self.txs_out:
            stream_struct("Q", f, tx_out.coin_value)
            tools.write_push_data([tx_out.script], f)
        return double_sha256(f.getvalue())

    def item_5(self, prior_tx_out_script):
        from pycoin.serialize import h2b
        if prior_tx_out_script[:2] == h2b('0014'):
            # P2WPKH program
            return h2b("1976a914") + prior_tx_out_script[2:] + h2b("88ac")
        raise ValueError("???")

    def signature_for_hash_type_segwit(self, script, tx_in_idx, hash_type):
        f = io.BytesIO()
        stream_struct("L", f, self.version)
        # calculate hash prevouts
        f.write(self.hash_prevouts())
        f.write(self.hash_sequence())
        tx_in = self.txs_in[tx_in_idx]
        f.write(tx_in.previous_hash)
        stream_struct("L", f, tx_in.previous_index)
        tx_out = self.unspents[tx_in_idx]
        f.write(self.item_5(tx_out.script))
        stream_struct("Q", f, tx_out.coin_value)
        stream_struct("L", f, tx_in.sequence)
        f.write(self.hash_outputs())
        stream_struct("L", f, self.lock_time)
        stream_struct("L", f, hash_type)
        return from_bytes_32(double_sha256(f.getvalue()))

    def is_signature_ok(self, tx_in_idx, flags=None, traceback_f=None):
        tx_in = self.txs_in[tx_in_idx]
        if tx_in.is_coinbase():
            return True
        if len(self.unspents) <= tx_in_idx:
            return False
        unspent = self.unspents[tx_in_idx]
        if unspent is None:
            return False
        tx_out_script = self.unspents[tx_in_idx].script

        def signature_for_hash_type_f(hash_type, script):
            return self.signature_hash(script, tx_in_idx, hash_type)

        witness = None
        if self.witnesses:
            witness = self.witnesses[tx_in_idx]
        
        return tx_in.verify(tx_out_script, signature_for_hash_type_f, self.lock_time,
                            witness=witness, flags=flags, traceback_f=traceback_f)

