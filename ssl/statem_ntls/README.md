NTLS State Machine Design
=========================

This file provides some guidance on the thinking behind the design of the
state machine code to aid future maintenance.

The message flow state machine is divided into a reading sub-state machine and a
writing sub-state machine. See the source comments in ntls_statem.c for a more
detailed description of the various states and transitions possible.

Conceptually the state machine component is designed as follows:

                          libssl
                             |
    -------------------------|-----ntls_statem.h------------------------------------
                             |
                      _______V____________________
                     |                            |
                     |    ntls_statem.c           |
                     |                            |
                     |    Core state machine code |
                     |____________________________|
    ntls_statem_local.h     ^          ^
                   _________|          |_______
                  |                            |
     _____________|____________   _____________|____________
    |                          | |                          |
    | ntls_statem_clnt.c       | | ntls_statem_srvr.c       |
    |                          | |                          |
    | NTLS client specific     | | NTLS server specific     |
    | state machine code       | | state machine code       |
    |__________________________| |__________________________|
                      |                   |
                      |                   |
                      |                   |
                 _____V___________________V___
                |                             |
                | ntls_statem_lib.c           |
                |                             |
                | Non core functions common   |
                | to both servers and clients |
                |_____________________________|
Note:

  - Receive a message first and then work out whether that is a valid
    transition - not the other way around (the other way causes lots of issues
    where we are expecting one type of message next but actually get something
    else)
  - Separate message flow state from handshake state (in order to better
    understand each)
    * message flow state = when to flush buffers; handling restarts in the
      event of NBIO events; handling the common flow of steps for reading a
      message and the common flow of steps for writing a message etc
    * handshake state = what handshake message are we working on now
  - Control complexity: only the state machine can change state: keep all
    the state changes local to the state machine component
  - GB/T 38636-2020 TLCP(Transport layer cryptography protocol) and GM/T
    0024-2014 SSL VPN specification are supported.
