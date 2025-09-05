#server purpose 
# accepts and listens to message from client
#receives messages from clients 
#echos the message back to client 
#manages connections and check who is online and handle disconnction



#imports asynchio library and websockets server and clients 
import asyncio
import websockets

#define asynchronous function 
async def echo(websocket):
    print("✅ Client connected")
    #listen for messages from client 
    try:
        async for message in websocket:
            #if messages is received prints in console 
            print(f"📩 Received: {message}")
            #send the same message back to client 
            await websocket.send(f"Echo: {message}")
            #if client disconnects show disconnected 
    except websockets.exceptions.ConnectionClosedOK:

        print("❌ Client disconnected")


#start the server on local host 8765 
async def main():
    async with websockets.serve(echo, "localhost", 8765):
        print("🚀 Server started on ws://localhost:8765")
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())
