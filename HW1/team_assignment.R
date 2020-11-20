library(PKI)

# 1) Generate keypair for ceu.edu and save it in pem format ------------------

key <- PKI.genRSAkey(bits = 2048L)
prv.pem <- PKI.save.key(key, private=TRUE)
pub.pem <- PKI.save.key(key, private=FALSE)

# 2) ceu.edu sends private pem file to visitor ------------------------------------

write(pub.pem, file="id_ceu_edu.pub")
write(prv.pem, file="id_ceu_edu")

# 3) visitor creates encrypted message using CEU's private key ------------------------

##load pem format and convert to key
pub.pem.loaded <- scan("id_ceu_edu.pub", what='list', sep='\n') 
pub.key.loaded <- PKI.load.key(pub.pem.loaded)

## encrprypt random message with CEU's private key
message <- 'Something that should be encrpyted'
bytes.to.encode = charToRaw(message)
encrypted <- PKI.encrypt(bytes.to.encode, pub.key.loaded)


# 4) visitor sends encrypted message to CEU ----------------------------------

writeBin(encrypted, file("encrypted_message.dat", "wb"))
close(file("encrypted_message.dat", "wb"))



# Adding second message ---------------------------------------------------

pub.pem.loaded <- scan("id_ceu_edu.pub", what='list', sep='\n') 
pub.key.loaded <- PKI.load.key(pub.pem.loaded)

message2 <- 'This shall be the big big message'
bytes.to.encode = charToRaw(message2)
encrypted <- PKI.encrypt(bytes.to.encode, pub.key.loaded)

writeBin(encrypted, file("encrypted_message2.dat", "wb"))
close(file("encrypted_message2.dat", "wb"))


# 5) CEU reads it's private key from disk + decrypts message -----------------

##load private key from disk + convert to key 
prv.pem.loaded <- scan("id_ceu_edu", what='list', sep='\n') 
prv.key.loaded <- PKI.load.key(prv.pem.loaded)

## read encrypted file from disk
read.binfile <- file("encrypted_message.dat", "rb")
reread.encrypted.data <- readBin(read.binfile, raw(), n=999999999) 
close(read.binfile)

## read second message
read.binfile2 <- file("encrypted_message2.dat", "rb")
reread.encrypted.data2 <- readBin(read.binfile2, raw(), n=999999999) 
close(read.binfile2)


## decrypt file with private key + print it on screen
decrypted_message <- rawToChar(PKI.decrypt(reread.encrypted.data, prv.key.loaded))
print(decrypted_message)

## second message
decrypted_message2 <- rawToChar(PKI.decrypt(reread.encrypted.data2, prv.key.loaded))
print(decrypted_message2)
