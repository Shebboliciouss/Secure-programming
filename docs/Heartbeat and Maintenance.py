    async def handle_heartbeat(self, websocket, data):
        """Handle peer heartbeat"""
        peer_id = data['peer_id']
        # Update last seen timestamp for peer
        # In full implementation, track peer health

    async def start_heartbeat(self):
        """Start heartbeat service"""
        while self.is_running:
            try:
                heartbeat_msg = {
                    'type': 'HEARTBEAT',
                    'server_id': self.server_id,
                    'timestamp': time.time()
                }
                
                # Send to all peers
                dead_peers = []
                for peer_id, websocket in self.peers.items():
                    try:
                        await websocket.send(json.dumps(heartbeat_msg))
                    except:
                        dead_peers.append(peer_id)
                
                # Clean up dead peers
                for peer_id in dead_peers:
                    await self.handle_peer_disconnection_by_id(peer_id)
                    
            except Exception as e:
                print(f"Heartbeat error: {e}")
            
            await asyncio.sleep(self.heartbeat_interval)

    async def handle_peer_disconnection(self, websocket):
        """Handle peer disconnection"""
        peer_id = None
        for pid, ws in self.peers.items():
            if ws == websocket:
                peer_id = pid
                break
                
        if peer_id:
            await self.handle_peer_disconnection_by_id(peer_id)

    async def handle_peer_disconnection_by_id(self, peer_id: str):
        """Handle peer disconnection by ID"""
        if peer_id in self.peers:
            del self.peers[peer_id]
        if peer_id in self.peer_public_keys:
            del self.peer_public_keys[peer_id]
        
        # Update user locations - users on disconnected peer are now unavailable
        users_to_remove = [uid for uid, sid in self.user_locations.items() if sid == peer_id]
        for user_id in users_to_remove:
            del self.user_locations[user_id]

    async def broadcast_to_peers(self, message: Dict, exclude_peer: str = None):
        """Broadcast message to all connected peers"""
        dead_peers = []
        for peer_id, websocket in self.peers.items():
            if peer_id == exclude_peer:
                continue
            try:
                await websocket.send(json.dumps(message))
            except:
                dead_peers.append(peer_id)
        
        for peer_id in dead_peers:
            await self.handle_peer_disconnection_by_id(peer_id)

    async def start_server(self):
        """Start the WebSocket server"""
        async with websockets.serve(self.handle_peer_connection, self.host, self.port):
            print(f"Server {self.server_id} listening on {self.host}:{self.port}")
            
            # Start heartbeat task
            heartbeat_task = asyncio.create_task(self.start_heartbeat())
            
            # Keep server running
            await asyncio.Future()

# Utility function to get user public key (simplified)
    def get_user_public_key(self, user_id: str) -> rsa.RSAPublicKey:
        """Get user's public key - in real implementation, this would be from a key server"""
        # Simplified - return server's public key for demo
        return self.public_key