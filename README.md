# Secure-programming
group 47 


#1. Start two servers

python3 -m src.server.server srv1 8765 --peer srv2:8766
python3 -m src.server.server srv2 8766

#srv1 runs on port 8765 and connects to peer srv2:8766
#srv2 runs on port 8766
