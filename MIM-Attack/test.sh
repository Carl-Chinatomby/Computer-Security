make
./mtm_pki init
./mtm_pki cert -g alice.priv alice.pub alice
./mtm_pki cert -g bob.priv bob.pub bob
./mtm_launcher