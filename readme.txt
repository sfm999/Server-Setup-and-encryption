
stuart fletcher miller
4096514
sfm999

README



RUNNING THE PROGRAM

To run this program, you'll need to have a working version of Python3.

I compiled this on Ubuntu on the following version:

No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 20.04.3 LTS
Release:	20.04
Codename:	focal


And I compiled it with the following version of python:

Python 3.8.10


I've listed any imports below for convenience:


	- hashlib
	- Crypto
	- socket
	- secrets
	- codecs
	- getpass

I believe these are all pre-installed with Python3 versions.

FILE STRUCTURE OF ZIP file

Ass1.zip should contain the following:

	- readme.txt
	- key_setup.py
	- reset.py
	- alice
		- alice_host.py
		- RC4.py
	- bob
		- bob_client.py
		- RC4.py 
		
If any of these files are missing, please let me know asap as I've had trouble with zip today but I believe I fixed the issue.

RUNNING INSTRUCTIONS

The first thing to do is start in the root directory given (Assignment_1), then run the following:

	python3 reset.py
	python3 key_setup.py

'reset.py' will make sure there are no pre-existing files in the directories given (only accounting for
ones produced as a product of 'key_setup.py').
'key_setup.py' will generate a key pair for alice, distribute her key to a file ('key.pem'), generate
a fingerprint of the public key and distribute that to Bob; then it finally generates the username
and password for Bob and distributes it to alice. We generate a simple password of 'pass1234' and a username
of 'Bob' to keep it simple.


Now you need to open another two terminal windows and direct the first to alice and bob's directories, respectively
(optionally you can open just one other and use your current window to navigate to alice or bob's directories).

To clarify, you should AT LEAST have two terminal windows/tabs open with one being in the directory 'Assignment_1/alice' 
and the other being in the directory 'Assignment_1/bob'.


Now, I will detail this step by step to get to the messaging part.

BEGIN STEPS


Step 1: On ALICE window, enter:

		python3 alice_host.py


Step 2: On BOB window, enter:

		python3 bob_client.py


Step 3: On BOB window, enter:

		Bob
		pass1234


Step 4: On BOB window, send your first message or follow on-screen instructions to quit.

Step 5: On ALICE window, reply with actual message or follow on-screen instructions to quit.


END STEPS

NOTE:

	That's really all there is to it. If you want a fail case, just simply run the program as normal but when you
	get to 'Step 3', you should (on another window) edit the key.pem file slightly to alter the keys, resulting
	in an error between during 'Step 3' where the verification of the public key fingerprint, by Bob, of Alice's
	said public key, will then fail due to the fingerprint not matching what Alice reads in and sends.

