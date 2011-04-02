yes "test" | head -1000 > a_file
make
./edu_encrypt my_key.pub a_file an_encrypted_file
./edu_decrypt my_key.priv an_encrypted_file a_decrypted_file
diff a_file a_decrypted_file

yes "test" | head -1015 > a_file
./edu_encrypt my_key.pub a_file an_encrypted_file
./edu_decrypt my_key.priv an_encrypted_file a_decrypted_file
diff a_file a_decrypted_file

touch a_empty_file
./edu_encrypt my_key.pub a_empty_file an_encrypted_file
./edu_decrypt my_key.priv an_encrypted_file a_decrypted_file
diff a_empty_file a_decrypted_file