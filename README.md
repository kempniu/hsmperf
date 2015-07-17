hsmperf
=======

Description
-----------

*hsmperf* is a simple tool for comparing hashing performance of different PKCS#11 providers by calculating digests of random 256-byte chunks of data. Think [`ods-hsmspeed`](https://github.com/opendnssec/opendnssec/blob/develop/libhsm/src/bin/hsmspeed.c), but just for SHA-{1,256,512}.

**Note:** currently this program does *not* benchmark DNSSEC signing speed.

The program is a bit rough around the edges in its current form. I decided to publish it mainly as a starting point for anyone who would like to implement their own PKCS#11-based tool.

What can I use this for?
------------------------

The original purpose of this tool was to determine whether using a network-attached HSM for calculating a lot of SHA-1 hashes is a good idea (it's not).

Currently there's not much more you can really do with this tool apart from comparing raw hashing performance of two PKCS#11 providers, but I'm sure you can come up with creative ways of enhancing the codebase with all kinds of awesomeness for your own needs.

Acknowledgment
--------------

Back in his [NLnet Labs](https://nlnetlabs.nl/) days, Jelte Jansen ([@twitjeb](https://twitter.com/twitjeb)) wrote a very noob-friendly [tutorial](https://nlnetlabs.nl/downloads/publications/hsm/hsm.pdf) about PKCS#11 programming in Linux. His work saved me a lot of time and is the basis for the program's structure.

Requirements
------------

 * Linux
 * GCC
 * Make

Compilation
-----------

    $ git clone https://github.com/kempniu/hsmperf.git
    $ make

Example output
--------------

Using [SoftHSMv2](https://github.com/opendnssec/SoftHSMv2) on a [Celeron G1610](http://ark.intel.com/pl/products/71072/Intel-Celeron-Processor-G1610-2M-Cache-2_60-GHz):

    $ SOFTHSM2_CONF=~/softhsm2.conf hsmperf -l /usr/lib64/softhsm/libsofthsm2.so -c 100000 -v
    Enter PIN: 
               SHA-1,   DigestInit: min   0.000442 msec, max   0.027979 msec, avg   0.000541 msec
               SHA-1, DigestUpdate: min   0.001092 msec, max   0.029391 msec, avg   0.001252 msec
               SHA-1,  DigestFinal: min   0.000552 msec, max   0.028812 msec, avg   0.000633 msec
               SHA-1,        TOTAL: min   0.002152 msec, max   0.031961 msec, avg   0.002426 msec
    
             SHA-256,   DigestInit: min   0.000436 msec, max   0.029825 msec, avg   0.000536 msec
             SHA-256, DigestUpdate: min   0.001924 msec, max   0.033392 msec, avg   0.002128 msec
             SHA-256,  DigestFinal: min   0.000786 msec, max   0.304436 msec, avg   0.000890 msec
             SHA-256,        TOTAL: min   0.003203 msec, max   0.307140 msec, avg   0.003554 msec
    
             SHA-512,   DigestInit: min   0.000470 msec, max   0.031087 msec, avg   0.000579 msec
             SHA-512, DigestUpdate: min   0.001448 msec, max   0.029963 msec, avg   0.001623 msec
             SHA-512,  DigestFinal: min   0.000939 msec, max   0.308098 msec, avg   0.001069 msec
             SHA-512,        TOTAL: min   0.002932 msec, max   0.310158 msec, avg   0.003271 msec

License
-------

*hsmperf* is released under the [GPLv2](https://www.gnu.org/licenses/gpl-2.0.html).
