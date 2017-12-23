# OSlab
Operating System 2017 lab----Linux virus


exploit.sh:

	1.infect

	2.download necessary files

	3.compile full-nelson.c & run full-nelson


full-nelson.c:

	1.exploit

	2.open insmod.sh


insmod.sh:

	1.open Makefile

	2.insmod hello.ko


Makefile:

	make hello(LKM)


hello.c:

	LKM code


run exploit.sh --->
	find & infect *.sh files --->
		download necessary files --->
			compile full-nelson --->
				exploit to get root --->
					make LKM --->
						insmod LKM --->
							BOOM!!!
