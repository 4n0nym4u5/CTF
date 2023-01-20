#!/usr/bin/python

# Enigma2017 CTF, "Broken Encryption"

import sys
import time       # for using a delay in network connections
import telnetlib  # don't try using raw sockets, you'll tear your hair out trying to send the right line feed character

__author__ = 'michael-myers'

# TODO: I'm interested in any more elegant way to block-slice a Python string like this.
# Split out every 16-byte (32-hex char) block of returned ciphertext:
def parse_challenge(challenge):
    ciphertext_blocks = [challenge[0:32], challenge[32:64], challenge[64:96],
                         challenge[96:128], challenge[128:160], challenge[160:192],
                         challenge[192:224], challenge[224:]]
    return ciphertext_blocks


# To attack AES-ECB, we will be exploiting the following facts:
#   * we do not know all of the plaintext but we control a substring of it.
#	* the controlled portion is at a known offset within the string.
#   * by varying our input length we can force the secret part onto a block boundary.
#   * we can choose our substring to be a full block of padding & align it at a boundary.
#   * if the message ends at a block boundary, the last 16-byte block will be all padding.
#   * thus we know when the secret part is block aligned; we'll see the same ciphertext.
#   * there is no nonce or IV or counter, so ciphertext is deterministic.
#   * by varying length of plaintext we can align the secret part such that there 
#		is only one unknown byte at a time being encrypted in the final block of output. 
#	* by varying one byte at a time, we can brute-force guess input blocks until we
#       match what we see in the final block, thus giving us one byte of the secret.
#   * we will limit our guesses to the ASCII range 0x20-0x7E for this particular challenge.
#
# Begin by changing the 2nd block of plaintext to n100000000000000, where n is a guess. 
# If the ciphertext[2nd block] == ciphertext[7th block] then the guess is correct,
# otherwise increment n.
def main():
    # If the Engima2017 servers are still up: enigma2017.hackcenter.com 7945
    if len(sys.argv) < 3:   # lol Python doesn't have an argc
        print 'Usage : python CTF-Challenge-Response.py hostname port'
        sys.exit()
    host = sys.argv[1]
    port = int(sys.argv[2])
    
    guessed_secret = ""

    # Our input pads to the end of the 1st block, then aligns a guess at block 2.
    # Because we need to constantly alter this value, we are making it a bytearray. 
    # Strings in Python are immutable and inappropriate to use for holding data.
    chosen_plaintext = bytearray("0123456789" + "1000000000000000")

    # Guess each byte of the secret, in succession, by manipulating the 2nd plaintext
    # block (bytes 10 through 26) and looking for a matched ciphertext in the final block:
    for secret_bytes_to_guess in range(0, 64):
        # Add in a new guessing byte at the appropriate position:
        chosen_plaintext.insert(10, "?")

        # Guess over and over different values until we get this byte:
        for guessed_byte in range(0x20, 0x7E):  # this is the printable ASCII range.
            chosen_plaintext[10] = chr(guessed_byte)

            tn = telnetlib.Telnet("enigma2017.hackcenter.com", 7945)
            tn.read_until("Agent number: ")

            # Telnet input MUST BE DELIVERED with a \r\n line ending. If you send
            # only the \n the remote end will silently error on your input and send back
            # partially incorrect ciphertext! Untold hours debugging that bullshit.
            # Here we carefully convert the bytearray to ASCII and then to a string type, 
            # or else telnetlib barfs because of the hell that is dynamic typing.
            send_string = str(chosen_plaintext.decode('ascii') + "\r\n")
            tn.write(send_string)

            challenge = tn.read_all()
            tn.close()
            # time.sleep(0.5)   # (optional) rate-limit if you're worried about getting banned.

            ciphertext_blocks = parse_challenge(challenge)
            print "Currently guessing: " + chosen_plaintext[10:26]  # 2nd block holds the guess
            print "Chosen vs. final ciphertext blocks: " + ciphertext_blocks[1] + " <- ? -> " + ciphertext_blocks[6]

            # We're always guessing in the 2nd block and comparing result vs the 7th block:
            if ciphertext_blocks[1] == ciphertext_blocks[6]:
                print "Guessed a byte of the secret: " + chr(guessed_byte)
                guessed_secret = chr(guessed_byte) + guessed_secret
                break   # Finish the inner loop immediately, back up to the outer loop.

    print "All guessed bytes: " + guessed_secret

    print("Done")


if __name__ == "__main__":
    main()
