about the RSA
(1)what is RSA
 * RSA is a kind of encryption algorithm. RSA algorithm steps is
 * a.  choose random 2 big prime number p,q
 * b.  compute n=p*q and f=(p-1)*(q-1)
 * c.  Select a random integer e, with 1 < e < f and gcd(e,f) ≡ 1.
 * d.  Calculate d, such that (e•d) mod f ≡ 1 or d=e^(-1) mod f
 * e.  we call the pair (n,e) as the public key and the pair (n,d) as private key
 * f.  m is the actual message and M is the encryption message. use M = m^e mod n to encrypt m
 * g.  use m=M^d mod n to decrypt the M and get the actual message.
(2)how to encrypt and decrypt
 * a.  the child thread RAS_create_public create public key (n,e)
 * b.  the child thread RAS_create_private create private key (n,d)
 * c.  the child thread RAS_encrypt_message encrypt the message
 * d.  the child thread RAS_decrypt_message decrypt the message
(3) support file to run RSA example
 * a.  (/cpu/cc2538/dev/)ecc-driver.h ,ecc-driver.c which include the driver for RSA basic operation such as big
 * number add,subtract,multiply,modInv,Expmod operation
 * b.  (/cpu/cc2538/dev/)RSA-algorithm.h,RSA-algorithm.c which include the RSA algorithm functions and data structure
 * c. the rsa-example docment is in the (/example/hello-world/hello-world-test.c)
(4)important note to RSA
 * a. The ModInv operation requires the modulus to be odd. but in RSA f=(q-1)*(p-1)must be even. so the normal
 d = ModInv(e, f) can not be used to calculate the MOdInv. so we use the following equation to solve the promble
 d = (1 + (f x (e – ModInv(f, e))) / e
 So with four additional basic PKCP operations, ModInv can also be used to find inverse values in case the
modulus is even.
 