#make create keys if missing
make
./edu_keygen my_key.priv my_key.pub

#large file tests
yes "test" | head -1000 > a_file
./edu_encrypt my_key.pub a_file an_encrypted_file
./edu_decrypt my_key.priv an_encrypted_file a_decrypted_file
diff a_file a_decrypted_file

#larger file tests
yes "test" | head -1015 > a_file
./edu_encrypt my_key.pub a_file an_encrypted_file
./edu_decrypt my_key.priv an_encrypted_file a_decrypted_file
diff a_file a_decrypted_file

#Empty file test
touch a_empty_file
./edu_encrypt my_key.pub a_empty_file an_encrypted_file
./edu_decrypt my_key.priv an_encrypted_file a_decrypted_file
diff a_empty_file a_decrypted_file

#exactly 16 bytes test
yes "carl is the mann" | head -1 > a_file
./edu_encrypt my_key.pub a_file an_encrypted_file
./edu_decrypt my_key.priv an_encrypted_file a_decrypted_file
diff a_file a_decrypted_file

#a little more than 16 bytes test
yes "carl is the mannaaaaaa" | head -1 > a_file
./edu_encrypt my_key.pub a_file an_encrypted_file
./edu_decrypt my_key.priv an_encrypted_file a_decrypted_file
diff a_file a_decrypted_file
