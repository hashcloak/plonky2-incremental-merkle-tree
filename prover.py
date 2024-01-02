#!python3

import sys
import hashlib
from base64 import b64encode, b64decode
import math
# HINT: why is hash_interna_node included?
from merkle_utils import MerkleProof, hash_internal_node, hash_leaf

merkle_proof_file = "merkle_proof.txt"   # File where merkle proof is written.

MAXHEIGHT = 20             # Max height of Merkle tree
NUM_LEAVES = 1000          # Number of leaves in Merkle Tree


def write_merkle_proof(filename, merkle_proof: MerkleProof):
    """Helper function that outputs the merkle proof to a file in a format for 
       it to be read easily by the verifier."""
    fp = open(filename, "w")
    print("leaf position: {pos:d}".format(pos=merkle_proof.pos), file=fp)
    print("leaf value: \"{leaf:s}\"".format(leaf=merkle_proof.leaf.decode('utf-8')), file=fp)
    print("Hash values in proof:", file=fp)
    for i in range(len(merkle_proof.hashes)):
        print("  {:s}".format(b64encode(merkle_proof.hashes[i]).decode('utf-8')), file=fp)
    fp.close()

def gen_leaves_for_merkle_tree():
    """Generates 1000 leaves for the merkle tree"""
    
    # The leaves never change and so they always produce the same 
    # Merkle root (ROOT in verifier.py)
    leaves = [b"data item " + str(i).encode() for i in range(NUM_LEAVES)]
    print('\nI generated #{} leaves for a Merkle tree.'.format(NUM_LEAVES))
    
    return leaves

def gen_merkle_proof(leaves, pos):
    """Takes as input a list of leaves and a leaf position.
    Returns the a the list of hashes that prove the leaf is in 
    the tree at position pos."""

    # yüksekliği direk alabiliriz.
    height = math.ceil(math.log(len(leaves),2))
    assert height < MAXHEIGHT, "Too many leaves."

    # hash all the leaves
    state = list(map(hash_leaf, leaves))  
    print(len(state))

    # state is the hash of the leaves
    # after state, I need to have the level hashes or hashes

    # Pad the list of hashed leaves to a power of two
    padlen = (2**height)-len(leaves)
    state += [b"\x00"] * padlen

    # initialize a list that will contain the hashes in the proof
    hashes = []

    level_pos = pos    # local copy of pos

    for level in range(height):
        new_state = []
        #######  YOUR CODE GOES HERE                              ######
        #######     to hash internal nodes in the tree use the    ######
        #######     function hash_internal_node(left,right)       ######
        # 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
        # let's say position is 8
        # I need to add hash position 8 and 7
        if level_pos % 2 == 1:
            selected_hash = hash_internal_node(state[level_pos - 1], state[level_pos])
        else:
            selected_hash = hash_internal_node(state[level_pos + 1], state[level_pos])
        
        new_state = list(map(hash))

    return hashes
    

### Main program
if __name__ == "__main__":

    # Read leaf number from command line
    # We generate a Merkle proof for this leaf
    pos = 743   # default leaf number
    # Aşağıdaki 2 satırda, eğer command line'a bir şey girersek,
    # o zaman onu position olarak al diyor
    # eğer girmezsek, o zaman default value olarak 743 al diyor.
    if len(sys.argv) > 1:
        pos = int(sys.argv[1])
        
    assert 0 <= pos < NUM_LEAVES, "Invalid leaf number"

    leaves = gen_leaves_for_merkle_tree()
    # Burada merkle tree için leaves generate ediyor. Leaves'i döndürüyor.
    #print(leaves)

    # Generate the merkle proof
    # Bu alt satıra bizim kod yazmamız gerekiyor ki hashes döndürsün
    # hashes demek, merkle proof anlamına geliyor.
    hashes = gen_merkle_proof(leaves, pos)

    merkle_proof = MerkleProof(leaves[pos], pos, hashes)
    print(merkle_proof.hashes) # Şu an hashes boş dönüyor. Bizim yapmamız gereken hashes'a ekleme yapmak.
    print(merkle_proof.pos)
    print(merkle_proof.leaf)

    # Write merkle proof to a file for the verifier to access
    write_merkle_proof(merkle_proof_file, merkle_proof)

    print('I generated a Merkle proof for leaf #{} in file {}\n'.format(pos,merkle_proof_file))
    sys.exit(0)



