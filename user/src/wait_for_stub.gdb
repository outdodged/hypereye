target remote localhost:1234

b $lstar

while($rax!=0x41414141)
    cont
end

printf"In syscall stub context\n"