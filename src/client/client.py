import asyncio
import websockets
#define the asynchronouse function hello
#and connect to port 
async def hello():
    uri = "ws://localhost:8765"
    #send message ti the client 
    async with websockets.connect(uri) as websocket:
        await websocket.send("Hello from client!")
        #then awaut reply from the server 
        reply = await websocket.recv()
        print(f"📩 Reply from server: {reply}")

if __name__ == "__main__":
    asyncio.run(hello())
