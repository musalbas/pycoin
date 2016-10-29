import io

from pycoin.encoding import double_sha256, from_bytes_32
from pycoin.intbytes import byte_to_int
from pycoin.serialize import b2h
from pycoin.serialize.bitcoin_streamer import (
    parse_struct, parse_bc_int, parse_bc_string,
    stream_struct, stream_bc_string
)

from pycoin.tx import Tx, TxIn, TxOut
from pycoin.tx.pay_to import script_obj_from_script, ScriptPayToScript
from pycoin.tx.script import opcodes, tools
from pycoin.tx.Tx import SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE

ZERO32 = b'\0' * 32


class TxSegwit(Tx):

    def __init__(self, *args, **kwargs):
        super(TxSegwit, self).__init__(*args, **kwargs)
        self.witnesses = []

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

    def stream(self, f, blank_solutions=False, include_unspents=False):
        is_segwit = any(len(witness) > 0 for witness in self.witnesses)
        stream_struct("L", f, self.version)
        if is_segwit:
            f.write(b'\0\1')
        stream_struct("I", f, len(self.txs_in))
        for t in self.txs_in:
            t.stream(f, blank_solutions=blank_solutions)
        stream_struct("I", f, len(self.txs_out))
        for t in self.txs_out:
            t.stream(f)
        if is_segwit:
            for witness in self.witnesses:
                stream_struct("I", f, len(witness))
                for w in witness:
                    stream_bc_string(f, w)
        stream_struct("L", f, self.lock_time)
        if include_unspents and not self.missing_unspents():
            self.stream_unspents(f)

    def set_witness(self, tx_idx_in, witness):
        witnesses = self.witnesses
        while len(witnesses) < len(self.txs_in):
            witnesses.append([])
        assert len(witnesses) == len(self.txs_in)
        for w in witness:
            assert isinstance(w, bytes)
        witnesses[tx_idx_in] = tuple(witness)

    def w_hash(self):
        pass

    def w_id(self):
        return b2h(self.w_hash())

    def solve(self, hash160_lookup, tx_in_idx, tx_out_script, hash_type=None, **kwargs):
        """
        Sign a standard transaction.
        hash160_lookup:
            An object with a get method that accepts a hash160 and returns the
            corresponding (secret exponent, public_pair, is_compressed) tuple or
            None if it's unknown (in which case the script will obviously not be signed).
            A standard dictionary will do nicely here.
        tx_in_idx:
            the index of the tx_in we are currently signing
        tx_out:
            the tx_out referenced by the given tx_in
        """
        if hash_type is None:
            hash_type = self.SIGHASH_ALL
        tx_in = self.txs_in[tx_in_idx]

        is_p2h = (len(tx_out_script) == 23 and byte_to_int(tx_out_script[0]) == opcodes.OP_HASH160 and
                  byte_to_int(tx_out_script[-1]) == opcodes.OP_EQUAL)
        if is_p2h:
            hash160 = ScriptPayToScript.from_script(tx_out_script).hash160
            p2sh_lookup = kwargs.get("p2sh_lookup")
            if p2sh_lookup is None:
                raise ValueError("p2sh_lookup not set")
            if hash160 not in p2sh_lookup:
                raise ValueError("hash160=%s not found in p2sh_lookup" %
                                 b2h(hash160))

            script_to_hash = p2sh_lookup[hash160]
        else:
            script_to_hash = tx_out_script

        # Leave out the signature from the hash, since a signature can't sign itself.
        # The checksig op will also drop the signatures from its hash.
        def signature_for_hash_type_f(hash_type, script):
            return self.signature_hash(script, tx_in_idx, hash_type)

        def witness_signature_for_hash_type(hash_type, script):
            return self.signature_for_hash_type_segwit(script, tx_in_idx, hash_type)

        signature_for_hash_type_f.witness = witness_signature_for_hash_type

        if tx_in.verify(tx_out_script, signature_for_hash_type_f, self.lock_time):
            return

        the_script = script_obj_from_script(tx_out_script)
        witness = []
        if len(self.witnesses) > tx_in_idx:
            witness = self.witnesses[tx_in_idx]
        solution = the_script.solve(
            hash160_lookup=hash160_lookup, signature_type=hash_type,
            existing_script=self.txs_in[tx_in_idx].script, existing_witness=witness,
            script_to_hash=script_to_hash, signature_for_hash_type_f=signature_for_hash_type_f, **kwargs)
        return solution

    def sign_tx_in(self, hash160_lookup, tx_in_idx, tx_out_script, hash_type=None, **kwargs):
        if hash_type is None:
            hash_type = self.SIGHASH_ALL
        r = self.solve(hash160_lookup, tx_in_idx, tx_out_script,
                       hash_type=hash_type, **kwargs)
        if isinstance(r, bytes):
            self.txs_in[tx_in_idx].script = r
        else:
            self.txs_in[tx_in_idx].script = r[0]
            self.set_witness(tx_in_idx, r[1])

    def verify_tx_in(self, tx_in_idx, tx_out_script, expected_hash_type=None):
        tx_in = self.txs_in[tx_in_idx]

        def signature_for_hash_type_f(hash_type, script):
            return self.signature_hash(script, tx_in_idx, hash_type)

        witness = None
        if self.witnesses:
            witness = self.witness[tx_in_idx]
        if not tx_in.verify(
                tx_out_script, signature_for_hash_type_f, expected_hash_type, witness=witness):
            raise ValidationFailureError(
                "just signed script Tx %s TxIn index %d did not verify" % (
                    b2h_rev(tx_in.previous_hash), tx_in_idx))

    def hash_prevouts(self, hash_type):
        if hash_type & SIGHASH_ANYONECANPAY:
            return ZERO32
        f = io.BytesIO()
        for tx_in in self.txs_in:
            f.write(tx_in.previous_hash)
            stream_struct("L", f, tx_in.previous_index)
        return double_sha256(f.getvalue())

    def hash_sequence(self, hash_type):
        if (
                (hash_type & SIGHASH_ANYONECANPAY) or
                ((hash_type & 0x1f) == SIGHASH_SINGLE) or
                ((hash_type & 0x1f) == SIGHASH_NONE)
        ):
            return ZERO32

        f = io.BytesIO()
        for tx_in in self.txs_in:
            stream_struct("L", f, tx_in.sequence)
        return double_sha256(f.getvalue())

    def hash_outputs(self, hash_type, tx_in_idx):
        txs_out = self.txs_out
        if hash_type & 0x1f == SIGHASH_SINGLE:
            if tx_in_idx >= len(txs_out):
                return ZERO32
            txs_out = txs_out[tx_in_idx:tx_in_idx+1]
        elif hash_type & 0x1f == SIGHASH_NONE:
            return ZERO32
        f = io.BytesIO()
        for tx_out in txs_out:
            stream_struct("Q", f, tx_out.coin_value)
            tools.write_push_data([tx_out.script], f)
        return double_sha256(f.getvalue())

    def segwit_signature_preimage(self, script, tx_in_idx, hash_type):
        f = io.BytesIO()
        stream_struct("L", f, self.version)
        # calculate hash prevouts
        f.write(self.hash_prevouts(hash_type))
        f.write(self.hash_sequence(hash_type))
        tx_in = self.txs_in[tx_in_idx]
        f.write(tx_in.previous_hash)
        stream_struct("L", f, tx_in.previous_index)
        tx_out = self.unspents[tx_in_idx]
        stream_bc_string(f, script)
        stream_struct("Q", f, tx_out.coin_value)
        stream_struct("L", f, tx_in.sequence)
        f.write(self.hash_outputs(hash_type, tx_in_idx))
        stream_struct("L", f, self.lock_time)
        stream_struct("L", f, hash_type)
        return f.getvalue()

    def signature_for_hash_type_segwit(self, script, tx_in_idx, hash_type):
        return from_bytes_32(double_sha256(self.segwit_signature_preimage(script, tx_in_idx, hash_type)))

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

        def witness_signature_for_hash_type(hash_type, script):
            return self.signature_for_hash_type_segwit(script, tx_in_idx, hash_type)

        signature_for_hash_type_f.witness = witness_signature_for_hash_type

        witness = None
        if self.witnesses:
            witness = self.witnesses[tx_in_idx]

        return tx_in.verify(tx_out_script, signature_for_hash_type_f, self.lock_time,
                            witness=witness, flags=flags, traceback_f=traceback_f)

