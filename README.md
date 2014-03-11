http://netsukuku.freaknet.org





# What is this?


Netsukuku is an alternative to the internet, It will have all of the features of the internet,
Such as websites, Instant messaging, File transfers, DNS, Etc. It functions as a
mesh network or a p2p net system that generates and sustains
itself autonomously. It is designed to handle an unlimited number of nodes
with minimal CPU and memory resources. 

Thanks to this feature it can be easily
used to build a worldwide distributed, anonymous and decentralised network,
separated from the Internet, without the support of any servers, ISPs or
authorities.

This net is composed by computers linked physically each other, Therefore it
isn't build upon any existing network. Netsukuku builds only the routes which
connects all the computers of the net. 
Although it can route through the internet if needed.
In other words, Netsukuku replaces the level 3 of the model iso/osi with
another routing protocol.

The Domain Name System is also replaced by a decentralised and distributed
system, Being the ANDNA system. (A Netsukuku Domain Name Architecture)

The complete features list of Netsukuku is here:
http://netsukuku.freaknet.org/files/doc/misc/Ntk_features_list

#For Documentation, Please read this! 

## http://netsukuku.github.io/netsukuku/annotated.html

Just search what ever you want to know, And be amazed with doxygen's glory! ^-^

In order to join to Netsukuku, Just install it and run it! Connect as many
nodes together as you want!

# Build and install

## Get the code!

    git clone git@github.com:Netsukuku/netsukuku.git 

The dependencies of netsukuku can be installed by running this command.

    sudo apt-get install zlibc libgmp-dev openssl libssl-dev libgee-dev libpth-dev libgcrypt11-dev autoconf cmake autogen mawk gawk

To compile the code you can do this:
   
    autoreconf -i
    ./configure && make 
    sudo make install

## Once installed

In order to start netsukuku on eth0, It is preferred to run:

    sudo ntkd -D -i eth0 -dd

CURRENTLY NON-FUNCTIONAL:
    
However, There are more options, Such as:

    sudo ntkd -D -i eth0 -r -I -dd
    
This will run netsukuku in restricted mode and share your internet connection.

(Netsukuku should be able to use any network interface you have, Even VPNs that emulate ethernet
such as tinc.)

## Manual Dependencies

You can manually download the dependencies of netsukuku if you want, 
Or use them for development. 

Here they are!

for the libgmp: https://gmplib.org/
the openssl library here: http://openssl.org
and finally the zlibs: http://zlib.net

## Old stuff

You can use this, But, I don't know if it works anymore.

SCons is a cooler way to install netsukuku:
http://www.scons.org/
(You should have installed at least the 2.4 version of Python in order to
avoid dirty bugs in scons)

Then go in the src/ directory and type:
    
    $ scons --help

That will show you all the options you can use in the build and installation
process. Finally execute:

    $ scons

The code will be compiled. If all went well install NetsukukuD with:

    # scons install

Now you should give a look at /etc/netsukuku.conf (or wherever you installed
it) and modify it for your needs, but generally the default options are good.

- Notes:

If you want to change some scons option to do another installation, (i.e. you
may want to reinstall it with another MANDIR path), you have to run:

    $ scons --clean


# Static Binaries and Packages

These packages are old, We will update them soon, Or you can if you want.

If you prefer to just install Netsukuku, without compiling it, you can
download the static binaries suitable to your platform. They come packed in
various formats (.tgz, .deb, .ipk).
The packages repository is at:
    http://netsukuku.freaknet.org/packages/ (Currently non-functional)
    
    https://launchpad.net/~michele-bini/+archive/ppa-mbxxii/+sourcepub/1032974/+listing-archive-extra
    
    (This archive contains unoffical packages, However, They have been tested, And function on Ubuntu 12.04 and earlier.)


# Kernel dependencies

I'm not sure if we need to do any of this anymore, But it is probably useful.

(The following probably is already, If not will be soon, Unnecessary/automated.)

On Linux be sure to have the following options set in your kernel .config.
These options are taken from linux-2.6.14.
 

 Networking options

    CONFIG_PACKET=y
    CONFIG_UNIX=y
    CONFIG_INET=y
    CONFIG_IP_MULTICAST=y
    CONFIG_IP_ADVANCED_ROUTER=y
    CONFIG_IP_MULTIPLE_TABLES=y
    CONFIG_IP_ROUTE_MULTIPATH=y
    CONFIG_NET_IPIP=y
    CONFIG_NETFILTER=y

and these from linux-2.6.16.19.

 Core Netfilter Configuration
 
    (I vaugely remember getting a conntrack error in the past, But it is gone now.)

    CONFIG_NETFILTER_XT_MATCH_CONNTRACK=y
    NETFILTER_XT_TARGET_CONNMARK=y

 IP: Netfilter Configuration

    CONFIG_IP_NF_IPTABLES=y
    CONFIG_IP_NF_FILTER=y
    CONFIG_IP_NF_TARGET_REJECT=y
    CONFIG_IP_NF_NAT=y
    CONFIG_IP_NF_NAT_NEEDED=y
    CONFIG_IP_NF_TARGET_MASQUERADE=y

If you are using modules you have to load them before launching the daemon.


# How to use it


Before doing anything do:

    $ man ntkd
    $ man andna

when you feel confortable and you are ready to dare run as root:

    # ntkd

then just wait... ^_-

(For the first times it's cool to use the -D option to see what happens).

- Note:
The daemon at startup takes the list of all the network interfaces which are
currently UP and it uses all of them to send and receive packets. If you want
to force the daemon to use specific interfaces you should use the B<-i>
option.


# Where to get in touch with us

## IRC

This is still true and active! Please join!

We live night and day in IRC, come to see us on channel
   #netsukuku
on the FreeNode irc server (irc.freenode.org).

## Mailing list

These mailing list should mostly still work, But they are not very active.

Subscribe to the netsukuku mailing to get help, be updated on the latest news
and discuss on its development.

To subscribe to the list, send a message to:
  netsukuku-subscribe@lists.dyne.org
or use the web interface:
  http://lists.dyne.org/mailman/listinfo/netsukuku
   
You can browse the archive here:
  http://lists.dyne.org/netsukuku/
  http://dir.gmane.org/gmane.network.peer-to-peer.netsukuku


# Bug report


{ Don't panic! }

If you encounter any bug, please report it.
Use the online bug track system:
  https://github.com/Netsukuku/netsukuku/issues
  
The rest is inactive, Please just use the link above until further notice.

  http://bugs.dyne.org/
or the mailing list:
  http://lists.dyne.org/netsukuku/
and explain what the problem is and if possible a way to reproduce it.


# Hack the code

Feel free to debug, patch, modify and eat the code. Then submit your results
to the mailing list. ^_-

However, It is preferred that you make your own github fork, And show it to us in the IRC or issues page.
Although, For smaller changes, You could use pastebin.com
But please note! Tell us exactly which file you are editing in pastebin, And tell us which line you are editing.

There is a lot to code too! If you are a Kung Foo coder, get on board and
help the development! For a start you can take a look
at the src/TODO file.

Still valuable! ^^^^

# License and that kind of stuff...

All the Netsukuku code is released under the GPL-2, please see the COPYING
file for more information.

The authors of Netsukuku and NetsukukuD are listed in the file AUTHORS.

This should be ammended in the future, As more authors come on-board.
