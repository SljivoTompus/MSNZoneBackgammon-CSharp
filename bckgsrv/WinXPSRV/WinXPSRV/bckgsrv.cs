using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

internal class Program
{
    private static void Main(string[] args)
    {
        var server = new ZoneGameServer("192.168.0.102", 28805);
        //var serverproxy = new ZoneGameServer("192.168.0.102", 28803);
        server.StartServer();
    }
}

public class ZoneGameServer
{
    private readonly string host;
    private readonly int port;
    private readonly TcpListener serverSocket;
    private readonly List<Player> lobby = new();
    private int playerCounter = 0;

    public ZoneGameServer(string host, int port)
    {
        this.host = host;
        this.port = port;
        serverSocket = new TcpListener(IPAddress.Parse(host), port);
    }

    public void StartServer()
    {
        serverSocket.Start();
        Console.WriteLine($"[SERVER] Started on {host}:{port}");

        while (true)
        {
            TcpClient client = serverSocket.AcceptTcpClient();
            playerCounter++;

            string clientIp = ((IPEndPoint)client.Client.RemoteEndPoint!).Address.ToString();
            Console.WriteLine($"[SERVER] New connection from {clientIp}, assigned Player ID: {playerCounter}");

            var player = new Player(playerCounter, client, clientIp);
            lobby.Add(player);

            var thread = new Thread(() => HandleClient(player));
            thread.Start();
        }
    }

    private void HandleClient(Player player)
    {
        try
        {
            NetworkStream stream = player.Socket.GetStream();
            byte[] buffer = new byte[1024];
            int bytesRead = stream.Read(buffer, 0, buffer.Length);

            if (bytesRead == 0)
            {
                Console.WriteLine($"[Player {player.Id}] Disconnected immediately.");
                return;
            }

            byte[] received = new byte[bytesRead];
            Array.Copy(buffer, received, bytesRead);
            Console.WriteLine($"[Player {player.Id}] Raw: {BitConverter.ToString(received)}");

            byte[] decrypted = XORDecrypt(received, 0xf8273645);

            // Prepoznaj signature
            if (decrypted.Length >= 4)
            {
                uint signature = BitConverter.ToUInt32(decrypted, 0);

                if (signature == 0x656E4F5A) // "ZoNe"
                {
                    Console.WriteLine($"[Player {player.Id}] Detected 'ZoNe' signature");

                    if (decrypted.Length >= 8)
                    {
                        ushort msgType = BitConverter.ToUInt16(decrypted, 4);
                        ushort payloadLength = BitConverter.ToUInt16(decrypted, 6);

                        Console.WriteLine($"[Player {player.Id}] ZoNe Message Type: 0x{msgType:X4}, Payload Length: {payloadLength}");

                        if (payloadLength + 8 <= decrypted.Length)
                        {
                            byte[] payload = new byte[payloadLength];
                            Array.Copy(decrypted, 8, payload, 0, payloadLength);

                            string payloadStr = Encoding.ASCII.GetString(payload);
                            Console.WriteLine($"[Player {player.Id}] Payload: {payloadStr}");

                            if (msgType == 0x0001)
                            {
                                Console.WriteLine($"[Player {player.Id}] Received client handshake payload.");
                            }
                        }
                    }
                }
                else if (signature == 0x474B4342) // 'BCKG'
                {
                    Console.WriteLine($"[Player {player.Id}] Detected 'BCKG' (Backgammon Game Message)");
                }
                uint sig = BitConverter.ToUInt32(decrypted, 0);

                if (sig == 0x656E4F5A) // ZoNe
                {
                    Console.WriteLine($"[Player {player.Id}] ➤ ZoNe Protocol Message (ZoNe)");
                }
                else if (sig == 0x7962626C) // lbby
                {
                    Console.WriteLine($"[Player {player.Id}] ➤ Lobby Protocol Message (lbby)");
                }
                else if (sig == 0x74756F72) // rout
                {
                    Console.WriteLine($"[Player {player.Id}] ➤ Routing Protocol Message (rout)");
                }
                else if (sig == 0x6365737A) // zsec
                {
                    Console.WriteLine($"[Player {player.Id}] ➤ Security Protocol Message (zsec)");
                }
                else
                {
                    Console.WriteLine($"[Player {player.Id}] Unknown signature: 0x{signature:X8}");
                }
            }

            // ASCII pregled
            Console.WriteLine($"[Player {player.Id}] Decrypted (HEX): {BitConverter.ToString(decrypted)}");
            string asciiSafe = Encoding.ASCII.GetString(decrypted.Select(b => (b >= 32 && b <= 126) ? b : (byte)'.').ToArray());
            Console.WriteLine($"[Player {player.Id}] ASCII safe: {asciiSafe}");

            // Pošalji BCKG (Backgammon) header
            byte[] protocolPacket = new byte[8];
            Array.Copy(Encoding.ASCII.GetBytes("BCKG"), 0, protocolPacket, 0, 4);
            protocolPacket[4] = 0x03;
            stream.Write(protocolPacket, 0, protocolPacket.Length);
            Console.WriteLine($"[Player {player.Id}] Sent binary handshake packet (BCKG v3).");

            // PAUZA PRE ZoNe odgovora
            Thread.Sleep(100);

            // XOR-šifrovani handshake response
            byte[] handshakePayload = Encoding.ASCII.GetBytes("ZoNeHandshakeSuccess");
            byte[] fullZoneResponse = CreateZoNePacket(0x0001, handshakePayload); // 0x0001 = handshake success
            stream.Write(fullZoneResponse, 0, fullZoneResponse.Length);
            Console.WriteLine($"[Player {player.Id}] Sent full ZoNe packet with handshake success.");

            // LOBBY
            SendRoutingInfoPacket(stream, player.Id);
            Thread.Sleep(100);

            /* 1. zRoomMsgAccessed
            byte[] accessedPacket = CreateRoomAccessedPacket(player.Id);
            stream.Write(accessedPacket, 0, accessedPacket.Length);

            // 2. zRoomMsgRoomInfo
            byte[] roomInfoPacket = CreateRoomInfoPacket(player.Id);
            stream.Write(roomInfoPacket, 0, roomInfoPacket.Length);

            // 3. zRoomMsgSeatResponse
            byte[] seatResponsePacket = CreateSeatResponsePacket(player.Id);
            stream.Write(seatResponsePacket, 0, seatResponsePacket.Length);

            Console.WriteLine("[Player] Sent lbby RoomInfo packet.");

            // 4. Opcioni welcome poruka*/
            SendLobbyWelcomePacket(stream, player.Id, $"Player{player.Id}");
            Thread.Sleep(100);


            // Posalji BCKG: zBGMsgNewMatch (0x0108)
            byte[] newMatchPacket = CreateBCKGPacket(0x0108);
            stream.Write(newMatchPacket, 0, newMatchPacket.Length);
            Console.WriteLine($"[Player {player.Id}] Sent BCKG NewMatch (0x108).");

            // Posalji BCKG: zBGMsgFirstMove (0x0109), payload = broj poena (4 bajta) + seat (2 bajta)
            List<byte> firstMovePayload = new();
            firstMovePayload.AddRange(BitConverter.GetBytes(3));  // npr. 3 poena
            firstMovePayload.AddRange(BitConverter.GetBytes((short)0)); // seat = 0

            byte[] firstMovePacket = CreateBCKGPacket(0x0109, firstMovePayload.ToArray());
            stream.Write(firstMovePacket, 0, firstMovePacket.Length);
            Console.WriteLine($"[Player {player.Id}] Sent BCKG FirstMove (0x109).");

            // Petlja za prijem narednih poruka
            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                byte[] next = new byte[bytesRead];
                Array.Copy(buffer, next, bytesRead);

                byte[] nextDecrypted = XORDecrypt(next, 0xf8273645);
                string msg = Encoding.ASCII.GetString(nextDecrypted);
                Console.WriteLine($"[Player {player.Id}] MSG (ASCII): {msg}");

                // Detekcija FirstMsg, FindMatch itd.
                if (msg.StartsWith("FirstMsg"))
                {
                    byte[] reply = XORDecrypt(Encoding.ASCII.GetBytes("FirstMsg_Ack"), 0xf8273645);
                    stream.Write(reply, 0, reply.Length);
                    Console.WriteLine($"[Player {player.Id}] Sent FirstMsg_Ack.");
                }
            }
            Console.WriteLine($"[Player {player.Id}] Added to lobby.");
            TryMatchPlayers();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Player {player.Id}] Error: {ex.Message}");
        }
        finally
        {
            player.Socket.Close();
            Console.WriteLine($"[Player {player.Id}] Disconnected.");
            lobby.Remove(player);
        }
    }

    /*private void HandleClient(Player player)
    {
        try
        {
            NetworkStream stream = player.Socket.GetStream();
            byte[] buffer = new byte[1024];
            int bytesRead = stream.Read(buffer, 0, buffer.Length);

            if (bytesRead == 0)
            {
                Console.WriteLine($"[Player {player.Id}] Disconnected immediately.");
                return;
            }

            byte[] received = new byte[bytesRead];
            Array.Copy(buffer, received, bytesRead);
            Console.WriteLine($"[Player {player.Id}] Raw: {BitConverter.ToString(received)}");

            byte[] decrypted = XORDecrypt(received, 0xf8273645);

            // Prepoznaj signature
            if (decrypted.Length >= 4)
            {
                uint signature = BitConverter.ToUInt32(decrypted, 0);

                /*if (signature == 0x656E4F5A) // 'ZoNe'
                {
                    Console.WriteLine($"[Player {player.Id}] Detected 'ZoNe' signature");
                    if (decrypted.Length >= 6)
                    {
                        ushort msgType = BitConverter.ToUInt16(decrypted, 4);
                        Console.WriteLine($"[Player {player.Id}] Message Type: 0x{msgType:X4}");
                    }
                }*****
                if (signature == 0x656E4F5A) // "ZoNe"
                {
                    Console.WriteLine($"[Player {player.Id}] Detected 'ZoNe' signature");

                    if (decrypted.Length >= 8)
                    {
                        ushort msgType = BitConverter.ToUInt16(decrypted, 4);
                        ushort payloadLength = BitConverter.ToUInt16(decrypted, 6);

                        Console.WriteLine($"[Player {player.Id}] ZoNe Message Type: 0x{msgType:X4}, Payload Length: {payloadLength}");

                        byte[] payload = new byte[payloadLength];
                        Array.Copy(decrypted, 8, payload, 0, payloadLength);

                        string payloadStr = Encoding.ASCII.GetString(payload);
                        Console.WriteLine($"[Player {player.Id}] Payload: {payloadStr}");

                        // Možemo reagovati na određeni tip poruke ovde
                        if (msgType == 0x0001) // Primer: Handshake potvrda
                        {
                            Console.WriteLine($"[Player {player.Id}] Received client handshake payload.");
                        }
                    }
                }
                else
                {
                    Console.WriteLine($"[Player {player.Id}] Unknown signature: 0x{signature:X8}");
                }
            }

            // ASCII pregled
            Console.WriteLine($"[Player {player.Id}] Decrypted (HEX): {BitConverter.ToString(decrypted)}");
            string asciiSafe = Encoding.ASCII.GetString(decrypted.Select(b => (b >= 32 && b <= 126) ? b : (byte)'.').ToArray());
            Console.WriteLine($"[Player {player.Id}] ASCII safe: {asciiSafe}");

            // Pošalji BCKG (Backgammon) header
            byte[] protocolPacket = new byte[8];
            Array.Copy(Encoding.ASCII.GetBytes("BCKG"), 0, protocolPacket, 0, 4); // Signature
            protocolPacket[4] = 0x03; // Version 3
            stream.Write(protocolPacket, 0, protocolPacket.Length);
            Console.WriteLine($"[Player {player.Id}] Sent binary handshake packet (BCKG v3).");
            while (true)
            {
                int len = stream.Read(buffer, 0, buffer.Length);
                if (len == 0)
                {
                    Console.WriteLine($"[Player {player.Id}] Client closed connection.");
                    break;
                }

                byte[] msg = new byte[len];
                Array.Copy(buffer, msg, len);

                byte[] decryptedNext = XORDecrypt(msg, 0xf8273645);
                string safe = Encoding.ASCII.GetString(decryptedNext);
                Console.WriteLine($"[Player {player.Id}] Next message: {safe}");
            }

            Thread.Sleep(100); // kratko čekanje

            // XOR-šifrovani handshake response
            byte[] payload = Encoding.ASCII.GetBytes("ZoNeHandshakeSuccess");
            byte[] fullPacket = CreateZoNePacket(0x0001, payload); // msgType = 0x0001 → handshake success
            stream.Write(fullPacket, 0, fullPacket.Length);
            Console.WriteLine($"[Player {player.Id}] Sent full ZoNe packet with handshake success.");

            //byte[] handshakeResponse = XORDecrypt(Encoding.ASCII.GetBytes("ZoNeHandshakeSuccess"), 0xf8273645);
            //stream.Write(handshakeResponse, 0, handshakeResponse.Length);
            //Console.WriteLine($"[Player {player.Id}] Sent handshake response.");

            // Petlja za prijem poruka
            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                byte[] next = new byte[bytesRead];
                Array.Copy(buffer, next, bytesRead);

                byte[] nextDecrypted = XORDecrypt(next, 0xf8273645);
                string msg = Encoding.ASCII.GetString(nextDecrypted);

                Console.WriteLine($"[Player {player.Id}] MSG (ASCII): {msg}");

                // Ako se u nekom trenutku očekuje "FirstMsg", "FindMatch", itd.
                if (msg.StartsWith("FirstMsg"))
                {
                    byte[] reply = XORDecrypt(Encoding.ASCII.GetBytes("FirstMsg_Ack"), 0xf8273645);
                    stream.Write(reply, 0, reply.Length);
                    Console.WriteLine($"[Player {player.Id}] Sent FirstMsg_Ack.");
                }

                // Dalji parsing po bgmsgs.h možeš da proširuješ ovde...
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Player {player.Id}] Error: {ex.Message}");
        }
        finally
        {
            player.Socket.Close();
            Console.WriteLine($"[Player {player.Id}] Disconnected.");
            lobby.Remove(player);
        }
    }*/
    //NOVO NAKON USPEHA!
    private byte[] CreateZoNePacket(ushort msgType, byte[] payload)
    {
        List<byte> packet = new();

        // Signature 'ZoNe' little-endian: 0x65 0x4E 0x6F 0x5A
        packet.AddRange(Encoding.ASCII.GetBytes("ZoNe"));

        // Message type
        packet.AddRange(BitConverter.GetBytes(msgType)); // ushort

        // Payload length
        packet.AddRange(BitConverter.GetBytes((ushort)payload.Length));

        // Payload
        packet.AddRange(payload);

        // XOR enkripcija
        return XORDecrypt(packet.ToArray(), 0xf8273645);
    }

    private static byte[] XORDecrypt(byte[] data, uint key)
    {
        byte[] keyBytes = BitConverter.GetBytes(key);
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            result[i] = (byte)(data[i] ^ keyBytes[i % 4]);
        return result;
    }

    // LOBBY_MATCHMAKING

    private void SendRoutingInfoPacket(NetworkStream stream, int playerId)
    {
        // Ovo je testni 'rout' paket sa minimalnim sadržajem
        byte[] payload = new byte[16];
        BitConverter.GetBytes(123456789).CopyTo(payload, 0);   // dummy user ID
        BitConverter.GetBytes(1).CopyTo(payload, 4);           // routing group
        BitConverter.GetBytes(0).CopyTo(payload, 8);           // flags
        BitConverter.GetBytes(0x10).CopyTo(payload, 12);       // version or capability mask
        byte[] packet = CreateZoneCustomPacket("rout", 0x0002, payload);
        stream.Write(packet, 0, packet.Length);
        Console.WriteLine($"[Player {playerId}] Sent 'rout' (Routing Info) packet.");
    }
    private byte[] CreateLobbyPacket(uint messageType, byte[] payload)
    {
        List<byte> packet = new();
        packet.AddRange(Encoding.ASCII.GetBytes("lbby")); // 'lbby'
        packet.AddRange(BitConverter.GetBytes(messageType)); // e.g. zRoomMsgRoomInfo = 1
        packet.AddRange(BitConverter.GetBytes(payload.Length));
        packet.AddRange(payload);
        return XORDecrypt(packet.ToArray(), 0xF8273645);
    }
    private byte[] CreateRoomInfoPayload()
    {
        List<byte> payload = new();
        payload.AddRange(BitConverter.GetBytes(1)); // gameID
        payload.AddRange(BitConverter.GetBytes(0)); // table
        payload.AddRange(BitConverter.GetBytes(0)); // seat
        payload.AddRange(BitConverter.GetBytes(0)); // game state
        return payload.ToArray();
    }

    private byte[] CreateUserInfoPayload(string internalName, string userName)
    {
        List<byte> payload = new();

        payload.AddRange(BitConverter.GetBytes(0x65647564)); // 'dude'
        payload.AddRange(BitConverter.GetBytes(1));          // protocolVersion
        payload.AddRange(BitConverter.GetBytes(0x00010000)); // clientVersion

        byte[] nameBytes = Encoding.ASCII.GetBytes(internalName.PadRight(16, '\0')); // zGameIDLen = 15 + \0
        payload.AddRange(nameBytes);

        byte[] userBytes = Encoding.ASCII.GetBytes(userName.PadRight(20, '\0')); // zUserNameLen = 19 + \0
        payload.AddRange(userBytes);

        return payload.ToArray();
    }

    // SVE OKO LBBY PORUKE PAKETA
    // Početna lbby poruka: Accessed
    private byte[] CreateRoomAccessedPacket(int userId)
    {
        List<byte> payload = new();
        payload.AddRange(BitConverter.GetBytes(userId));     // ZUserID (4)
        payload.AddRange(BitConverter.GetBytes((ushort)1));  // numTables (2)
        payload.AddRange(BitConverter.GetBytes((ushort)2));  // numSeatsPerTable (2)
        payload.AddRange(BitConverter.GetBytes(0u));         // gameOptions (4)
        payload.AddRange(BitConverter.GetBytes(1u));         // groupID (4)
        payload.AddRange(BitConverter.GetBytes(0u));         // maskRoomCmdPrivs (4)

        return CreateLobbyPacket(1, payload.ToArray()); // zRoomMsgAccessed = 1
    }
    private byte[] CreateRoomInfoPacket(int userId)
    {
        string username = "Guest";
        byte[] nameBytes = Encoding.ASCII.GetBytes(username.PadRight(21, '\0'));

        List<byte> payload = new();
        payload.AddRange(BitConverter.GetBytes(userId));      // ZUserID
        payload.AddRange(BitConverter.GetBytes((ushort)1));   // numTables
        payload.AddRange(BitConverter.GetBytes((ushort)2));   // numSeatsPerTable
        payload.AddRange(BitConverter.GetBytes(0u));          // gameOptions
        payload.AddRange(BitConverter.GetBytes((ushort)1));   // numPlayers
        payload.AddRange(BitConverter.GetBytes((ushort)1));   // numTableInfos

        // players[0]
        payload.AddRange(BitConverter.GetBytes(userId));              // userID
        payload.AddRange(nameBytes);                                  // userName[21]
        payload.AddRange(BitConverter.GetBytes(0u));                  // hostAddr
        payload.AddRange(BitConverter.GetBytes(0u));                  // timeSuspended
        payload.AddRange(BitConverter.GetBytes(20u));                 // latency
        payload.AddRange(BitConverter.GetBytes((short)1200));         // rating
        payload.AddRange(BitConverter.GetBytes((short)100));          // gamesPlayed
        payload.AddRange(BitConverter.GetBytes((short)5));            // gamesAbandoned
        payload.AddRange(BitConverter.GetBytes((short)0));            // rfu

        // tables[0]
        payload.AddRange(BitConverter.GetBytes((short)0)); // tableID
        payload.AddRange(BitConverter.GetBytes((short)0)); // status = idle
        for (int i = 0; i < 2; i++)
            payload.AddRange(BitConverter.GetBytes(0u));   // empty seats
        for (int i = 0; i < 2; i++)
            payload.Add((byte)0);                          // votes

        return CreateLobbyPacket(2, payload.ToArray()); // zRoomMsgRoomInfo = 2
    }
    private byte[] CreateSeatResponsePacket(int userId)
    {
        List<byte> payload = new();
        payload.AddRange(BitConverter.GetBytes(userId));     // ZUserID
        payload.AddRange(BitConverter.GetBytes(0u));         // gameID
        payload.AddRange(BitConverter.GetBytes((short)0));   // table
        payload.AddRange(BitConverter.GetBytes((short)0));   // seat
        payload.AddRange(BitConverter.GetBytes((short)0));   // action = zRoomSeatActionSitDown
        payload.AddRange(BitConverter.GetBytes((short)0));   // rfu
        return CreateLobbyPacket(8, payload.ToArray());
    }
    // /////////////////////////////////////////////////////////////////////////////////////////
    private void SendLobbyWelcomePacket(NetworkStream stream, int userId, string nickname)
    {
        byte[] payload = new byte[24];

        // userID
        BitConverter.GetBytes(userId).CopyTo(payload, 0);

        // roomID (0 za početak)
        BitConverter.GetBytes(0).CopyTo(payload, 4);

        // nickname (do 16 bajtova, ASCII, null-terminated/padded)
        byte[] nickBytes = Encoding.ASCII.GetBytes(nickname);
        Array.Copy(nickBytes, 0, payload, 8, Math.Min(nickBytes.Length, 16));

        byte[] packet = CreateZoneProtocolPacket("lbby", 0x0001, payload); // msgType 0x0001 → Welcome
        stream.Write(packet, 0, packet.Length);
        Console.WriteLine($"[Player] Sent 'lbby' (Lobby Welcome) packet.");
    }

    private byte[] CreateZoneProtocolPacket(string signature, ushort msgType, byte[] payload)
    {
        List<byte> packet = new();

        // Signature (4 bajta)
        packet.AddRange(Encoding.ASCII.GetBytes(signature));

        // msgType (2 bajta)
        packet.AddRange(BitConverter.GetBytes(msgType));

        // payload length (2 bajta)
        packet.AddRange(BitConverter.GetBytes((ushort)payload.Length));

        // payload
        packet.AddRange(payload);

        // XOR
        return XORDecrypt(packet.ToArray(), 0xf8273645);
    }

    private byte[] CreateBCKGPacket(ushort msgType, byte[]? payload = null)
    {
        payload ??= Array.Empty<byte>();

        List<byte> packet = new();
        packet.AddRange(Encoding.ASCII.GetBytes("BCKG"));                // Signature
        packet.AddRange(BitConverter.GetBytes(msgType));                 // Msg type
        packet.AddRange(BitConverter.GetBytes((ushort)payload.Length)); // Length
        packet.AddRange(payload);                                       // Payload

        return packet.ToArray(); // BCKG paketi se ne XOR-uju!
    }


    private byte[] CreateZoneCustomPacket(string signature, ushort msgType, byte[] payload)
    {
        List<byte> packet = new();

        // Signature mora biti tačno 4 bajta
        if (signature.Length != 4)
            throw new ArgumentException("Signature must be 4 characters");

        packet.AddRange(Encoding.ASCII.GetBytes(signature));       // 'rout', 'lbby'
        packet.AddRange(BitConverter.GetBytes(msgType));           // Message type
        packet.AddRange(BitConverter.GetBytes((ushort)payload.Length)); // Payload length
        packet.AddRange(payload);                                  // Sam payload

        return XORDecrypt(packet.ToArray(), 0xf8273645);           // Šifrovano kao i sve ostalo
    }

    private void TryMatchPlayers()
    {
        lock (lobby)
        {
            if (lobby.Count >= 2)
            {
                var p1 = lobby[0];
                var p2 = lobby[1];
                lobby.RemoveRange(0, 2);

                Console.WriteLine($"[SERVER] Matched Player {p1.Id} vs Player {p2.Id}");

                ThreadPool.QueueUserWorkItem(_ => StartBackgammonMatch(p1, p2));
            }
        }
    }

    //HU-HA NAJLAGA STARTMATCHMAKING
    private void StartBackgammonMatch(Player p1, Player p2)
    {
        try
        {
            Console.WriteLine($"[SERVER] Starting match: Player {p1.Id} vs Player {p2.Id}");

            // Slanje poruke "New Match Started"
            string newMatchMsg = "NewMatchStarted"; // test string, menjaćeš kad budemo koristili pravu strukturu iz bgmsgs.h
            byte[] newMatchPayload = Encoding.ASCII.GetBytes(newMatchMsg);
            byte[] packet1 = CreateZoNePacket(0x1001, newMatchPayload); // 0x1001 = fiktivni msgType za "new match"
            p1.Socket.GetStream().Write(packet1, 0, packet1.Length);
            p2.Socket.GetStream().Write(packet1, 0, packet1.Length);
            Console.WriteLine($"[SERVER] Sent match start notice to both players.");

            // DiceRoll test (fiksirane vrednosti zarad testiranja)
            byte[] diceInfo = new byte[] { 0x01, 0x05 }; // primer: igrač 1 baca 1 i 5
            byte[] dicePacket = CreateZoNePacket(0x1002, diceInfo); // 0x1002 = test ID za DiceRoll

            p1.Socket.GetStream().Write(dicePacket, 0, dicePacket.Length);
            p2.Socket.GetStream().Write(dicePacket, 0, dicePacket.Length);
            Console.WriteLine($"[SERVER] Sent DiceRoll to both players.");

            // ... ovde dodaj ostale poruke tipa FirstMove, TurnNotation itd.
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SERVER] Error during match start: {ex.Message}");
        }
    }

}

public class Player
{
    public int Id { get; }
    public TcpClient Socket { get; }
    public string IP { get; }

    public Player(int id, TcpClient socket, string ip)
    {
        Id = id;
        Socket = socket;
        IP = ip;
    }
}
