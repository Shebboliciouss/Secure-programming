# src/server/state.py
# Centralized state management for the server

from src.crypto import rsa_crpt

class ServerState:
    """Manages all server state according to spec Section 5.2"""
    
    def __init__(self, server_id, host, port, is_introducer=False):
        # Server identity
        self.server_id = server_id
        self.host = host
        self.port = port
        self.is_introducer = is_introducer
        
        # Cryptographic keys
        self.private_key, self.public_key = rsa_crpt.generate_rsa_keypair()
        
        # Required tables (Section 5.2)
        self.servers = {}              # server_id -> websocket Link
        self.server_addrs = {}         # server_id -> (host, port)
        self.local_users = {}          # user_id -> websocket Link
        self.user_locations = {}       # user_id -> "local" | server_id
        
        # Additional mappings
        self.user_keys = {}            # user_id -> pubkey
        self.usernames = {}            # user_id -> username
        self.username_to_id = {}       # username -> user_id
        self.server_pubkeys = {}       # server_id -> pubkey
        
        # Health tracking
        self.last_heartbeat = {}       # server_id -> timestamp
        
        # Bootstrap configuration
        self.bootstrap_servers = []    # List of introducer servers
    
    def add_server(self, server_id, ws, host, port, pubkey=None):
        """Register a new server connection"""
        self.servers[server_id] = ws
        self.server_addrs[server_id] = (host, port)
        if pubkey:
            self.server_pubkeys[server_id] = pubkey
    
    def remove_server(self, server_id):
        """Remove a server connection"""
        self.servers.pop(server_id, None)
        self.server_addrs.pop(server_id, None)
        self.server_pubkeys.pop(server_id, None)
        self.last_heartbeat.pop(server_id, None)
    
    def add_local_user(self, user_id, ws, username, pubkey):
        """Register a local user connection"""
        self.local_users[user_id] = ws
        self.user_locations[user_id] = "local"
        self.usernames[user_id] = username
        self.username_to_id[username] = user_id
        self.user_keys[user_id] = pubkey
    
    def remove_local_user(self, user_id):
        """Remove a local user"""
        username = self.usernames.get(user_id)
        self.local_users.pop(user_id, None)
        self.user_locations.pop(user_id, None)
        self.usernames.pop(user_id, None)
        self.user_keys.pop(user_id, None)
        if username:
            self.username_to_id.pop(username, None)
        return username
    
    def add_remote_user(self, user_id, server_id, username=None, pubkey=None):
        """Register a user on a remote server"""
        self.user_locations[user_id] = server_id
        if username:
            self.usernames[user_id] = username
            self.username_to_id[username] = user_id
        if pubkey:
            self.user_keys[user_id] = pubkey
    
    def remove_remote_user(self, user_id, server_id):
        """Remove a remote user (only if they're still on that server)"""
        if self.user_locations.get(user_id) == server_id:
            username = self.usernames.get(user_id)
            self.user_locations.pop(user_id, None)
            self.usernames.pop(user_id, None)
            self.user_keys.pop(user_id, None)
            if username:
                self.username_to_id.pop(username, None)
            return True
        return False
    
    def get_all_users(self):
        """Get all users (local and remote)"""
        return set(self.local_users.keys()) | set(self.user_locations.keys())
    
    def is_local_user(self, user_id):
        """Check if user is local"""
        return user_id in self.local_users and self.user_locations.get(user_id) == "local"
    
    def get_user_location(self, user_id):
        """Get where a user is located"""
        return self.user_locations.get(user_id)
    
    def resolve_username(self, username_or_id):
        """Resolve username to user_id, or return as-is if already an ID"""
        return self.username_to_id.get(username_or_id, username_or_id)