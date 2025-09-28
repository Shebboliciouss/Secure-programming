    async def handle_peer_deliver(self, data: Dict):
        """Handle message delivery from peer"""
        target_user = data['target_user']
        message = data['message']
        
        if target_user in self.local_users:
            # User is local, deliver directly
            await self.local_users[target_user].send(json.dumps(message))
        else:
            # User not found, queue message
            if target_user not in self.message_queues:
                self.message_queues[target_user] = []
            self.message_queues[target_user].append(message)

    async def route_message_to_user(self, target_user: str, message: Dict):
        """Route message to user, whether local or remote"""
        if target_user in self.local_users:
            # Local delivery
            await self.local_users[target_user].send(json.dumps(message))
        elif target_user in self.user_locations:
            # Remote delivery via peer
            target_server = self.user_locations[target_user]
            if target_server in self.peers and target_server != self.server_id:
                deliver_message = {
                    'type': 'PEER_DELIVER',
                    'target_user': target_user,
                    'message': message,
                    'timestamp': time.time()
                }
                await self.peers[target_server].send(json.dumps(deliver_message))
        else:
            # Queue for later delivery
            if target_user not in self.message_queues:
                self.message_queues[target_user] = []
            self.message_queues[target_user].append(message)

    async def handle_group_message(self, from_user: str, data: Dict):
        """Handle group message from user"""
        group_id = data['group_id']
        content = data['content']
        content_sig = data['content_sig']
        
        # Verify signature
        if not self.verify_user_signature(from_user, content, content_sig):
            print(f"Invalid signature for group message from {from_user}")
            return
        
        if group_id not in self.group_members or from_user not in self.group_members[group_id]:
            print(f"User {from_user} not in group {group_id}")
            return
        
        # Get group key and encrypt message
        group_key = self.groups[group_id]['aes_key']
        encrypted_content = self.aes_encrypt(content, group_key)
        
        # Create group message
        group_message = {
            'type': 'MSG_GROUP',
            'group_id': group_id,
            'from_user': from_user,
            'encrypted_content': encrypted_content,
            'content_sig': content_sig,
            'version': self.group_versions[group_id],
            'timestamp': time.time()
        }
        
        # Fan out to all group members
        await self.fan_out_group_message(group_id, group_message)

    async def fan_out_group_message(self, group_id: str, message: Dict):
        """Fan out group message to all members"""
        if group_id not in self.group_members:
            return
            
        for member in self.group_members[group_id]:
            await self.route_message_to_user(member, message)

    async def handle_group_join(self, from_user: str, data: Dict):
        """Handle user joining a group"""
        group_id = data['group_id']
        
        if group_id not in self.groups:
            # Create new group
            group_key = self.generate_aes_key()
            self.groups[group_id] = {
                'aes_key': group_key,
                'admin': from_user,
                'created': time.time()
            }
            self.group_members[group_id] = set()
            self.group_versions[group_id] = 1
        
        # Add user to group
        self.group_members[group_id].add(from_user)
        self.group_versions[group_id] += 1
        
        # Share group key with user
        await self.share_group_key(group_id, from_user)
        
        # Notify group members
        await self.broadcast_group_update(group_id, 'USER_JOINED', from_user)

    async def share_group_key(self, group_id: str, user_id: str):
        """Share group key with user using their public key"""
        if user_id in self.local_users:
            # Local user - get their public key from handshake (simplified)
            # In real implementation, you'd have user public keys stored
            group_key = self.groups[group_id]['aes_key']
            encrypted_key = self.rsa_encrypt(base64.b64encode(group_key).decode('utf-8'), 
                                           self.get_user_public_key(user_id))
            
            key_message = {
                'type': 'GROUP_KEY_SHARE',
                'group_id': group_id,
                'encrypted_key': encrypted_key,
                'version': self.group_versions[group_id],
                'timestamp': time.time()
            }
            
            await self.local_users[user_id].send(json.dumps(key_message))