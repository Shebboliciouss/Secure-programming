    async def handle_peer_connection(self, websocket, path):
        """Handle incoming peer connections"""
        try:
            async for message in websocket:
                data = json.loads(message)
                message_type = data.get('type')
                
                if message_type == 'PEER_HELLO_JOIN':
                    await self.handle_peer_hello_join(websocket, data)
                elif message_type == 'PEER_HELLO_LINK':
                    await self.handle_peer_hello_link(websocket, data)
                elif message_type == 'USER_ADVERTISE':
                    await self.handle_user_advertise(data)
                elif message_type == 'USER_REMOVE':
                    await self.handle_user_remove(data)
                elif message_type == 'PEER_DELIVER':
                    await self.handle_peer_deliver(data)
                elif message_type == 'HEARTBEAT':
                    await self.handle_heartbeat(websocket, data)
                elif message_type == 'GROUP_UPDATE':
                    await self.handle_group_update(data)
                    
        except websockets.exceptions.ConnectionClosed:
            await self.handle_peer_disconnection(websocket)

    async def handle_peer_hello_join(self, websocket, data):
        """Handle new peer joining the mesh"""
        peer_id = data['peer_id']
        peer_public_key = self.load_peer_public_key(data['public_key'])
        
        self.peers[peer_id] = websocket
        self.peer_public_keys[peer_id] = peer_public_key
        
        # Send welcome with current peer list
        welcome_message = {
            'type': 'PEER_WELCOME',
            'server_id': self.server_id,
            'peers': list(self.peers.keys()),
            'user_locations': self.user_locations,
            'timestamp': time.time()
        }
        
        await websocket.send(json.dumps(welcome_message))
        
        # Advertise new peer to existing peers
        await self.broadcast_to_peers({
            'type': 'PEER_ANNOUNCE',
            'peer_id': peer_id,
            'public_key': data['public_key'],
            'timestamp': time.time()
        }, exclude_peer=peer_id)

    async def handle_peer_hello_link(self, websocket, data):
        """Handle peer link establishment"""
        peer_id = data['peer_id']
        peer_public_key = self.load_peer_public_key(data['public_key'])
        
        self.peers[peer_id] = websocket
        self.peer_public_keys[peer_id] = peer_public_key
        
        # Acknowledge the link
        ack_message = {
            'type': 'PEER_LINK_ACK',
            'server_id': self.server_id,
            'timestamp': time.time()
        }
        await websocket.send(json.dumps(ack_message))

    async def connect_to_peer(self, peer_host: str, peer_port: int, peer_id: str):
        """Connect to a remote peer"""
        try:
            uri = f"ws://{peer_host}:{peer_port}"
            websocket = await websockets.connect(uri)
            
            # Send join hello
            join_message = {
                'type': 'PEER_HELLO_JOIN',
                'peer_id': self.server_id,
                'public_key': self.get_public_key_pem(),
                'timestamp': time.time()
            }
            
            await websocket.send(json.dumps(join_message))
            return websocket
            
        except Exception as e:
            print(f"Failed to connect to peer {peer_id}: {e}")
            return None