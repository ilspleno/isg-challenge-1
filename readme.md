Usage
=====
    
    Usage: netscan.rb [options]
    
    Specific settings:
        -n, --network CIDR               Network(s) to scan. Specify as a.b.c.d/n
                                         example: 10.14.0.0/16
        -a, --approved [LIST]            A (optional) comma separated list of hosts that are approved
        -p, --port NUMBER                A port number to scan for connectivity. Specify multiple times for multiple ports. Default is 80.
        -o, --output FILENAME            Filename to write report to (netscan.log is the default)
        -t, --test                       Test for an HTTP response in addition to an open port
        -v, --[no-]verbose               Run verbosely


Example output
==============

    +---------------------------+---------------------------------------+-----------------------------------+
    | Time                      | Host                                  | Ports (* indicates HTTP response) |
    +---------------------------+---------------------------------------+-----------------------------------+
    | 2016-09-27 15:53:44 -0400 | 10.0.1.1(router.example.net)          | 22,80*,9090*                      |
    | 2016-09-27 15:53:45 -0400 | 10.0.1.2(nighthawk.example.net)       | 80*                               |
    | 2016-09-27 15:53:46 -0400 | 10.0.1.6(m4100.example.net)           | 80*                               |
    | 2016-09-27 15:55:01 -0400 | 10.0.1.156(server2.example.net)       | 22                                |
    | 2016-09-27 15:55:28 -0400 | 10.0.1.211(HPB2844D.example.net)      | 8080*                             |
    | 2016-09-27 15:55:31 -0400 | 10.0.1.218(server1.example.net)       | 22                                |
    | 2016-09-27 15:55:40 -0400 | 10.0.1.236(server3.example.net)       | 22                                |
    | 2016-09-27 15:55:46 -0400 | 10.0.1.249(mailx.example.net)         | 22                                |
    +---------------------------+---------------------------------------+-----------------------------------+

Example Command Line
====================

    ./netscan.rb -n 10.0.1.0/24 -p 22 -p 80 -p 8080 -p 9090 -p 113 -a 10.0.1.4 -o myscan.log -v                                
