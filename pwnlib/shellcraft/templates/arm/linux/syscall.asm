<%
  from pwnlib.shellcraft import arm
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
%>
<%page args="syscall = None, *args"/>
<%docstring>
Args: [syscall_number, \*args]
    Does a syscall

Any of the arguments can be expressions to be evaluated by :func:`pwnlib.constants.eval`.
</%docstring>
<%
  regs = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6']

  if isinstance(syscall, (str, unicode)) and syscall.startswith('SYS_'):
      syscall_repr = syscall[4:] + "(%s)"
  else:
      syscall_repr = 'syscall(%s)'

  not_none = lambda x: x != None
  syscall_repr += ', '.join(map(repr, args))
%>\
    /* call ${syscall_repr} */
% for dst, src in zip(regs, args):
    ${arm.mov(dst, src)}
% endfor
    svc 0
