    async def handle_user_connection(self, websocket, path):
        """Handle user connections"""
        user_id = None
        try:
            async for message in websocket:
                data = json.loads(message)
                message_type = data.get('type')
                
                if message_type == 'USER_HELLO':
                    user_id = data['user_id']
                    await self.handle_user_hello(websocket, user_id, data)
                elif message_type == 'MSG_GROUP':
                    await self.handle_group_message(user_id, data)
                elif message_type == 'GROUP_JOIN':
                    await self.handle_group_join(user_id, data)
                elif message_type == 'GROUP_LEAVE':
                    await self.handle_group_leave(user_id, data)
                    
        except websockets.exceptions.ConnectionClosed:
            if user_id:
                await self.handle_user_disconnect(user_id)

    async def handle_user_hello(self, websocket, user_id: str, data: Dict):
        """Handle user registration"""
        self.local_users[user_id] = websocket
        self.user_locations[user_id] = self.server_id
        
        # Advertise user presence to all peers
        await self.broadcast_to_peers({
            'type': 'USER_ADVERTISE',
            'user_id': user_id,
            'server_id': self.server_id,
            'timestamp': time.time()
        })
        
        # Send pending messages
        if user_id in self.message_queues:
            for message in self.message_queues[user_id]:
                await websocket.send(json.dumps(message))
            del self.message_queues[user_id]

    async def handle_user_advertise(self, data: Dict):
        """Handle user presence advertisement from peers"""
        user_id = data['user_id']
        server_id = data['server_id']
        self.user_locations[user_id] = server_id

    async def handle_user_remove(self, data: Dict):
        """Handle user removal advertisement"""
        user_id = data['user_id']
        if user_id in self.user_locations:
            del self.user_locations[user_id]

    async def handle_user_disconnect(self, user_id: str):
        """Handle user disconnection"""
        if user_id in self.local_users:
            del self.local_users[user_id]
            
        # Notify peers about user departure
        await self.broadcast_to_peers({
            'type': 'USER_REMOVE',
            'user_id': user_id,
            'server_id': self.server_id,
            'timestamp': time.time()
        })