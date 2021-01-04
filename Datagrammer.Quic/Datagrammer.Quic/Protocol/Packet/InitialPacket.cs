namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct InitialPacket
    {
        private InitialPacket(PacketVersion version,
                              PacketConnectionId destinationConnectionId,
                              PacketConnectionId sourceConnectionId,
                              PacketToken token,
                              PacketNumber number,
                              MemoryBuffer payload)
        {
            Version = version;
            DestinationConnectionId = destinationConnectionId;
            SourceConnectionId = sourceConnectionId;
            Token = token;
            Number = number;
            Payload = payload;
        }

        public PacketVersion Version { get; }

        public PacketConnectionId DestinationConnectionId { get; }

        public PacketConnectionId SourceConnectionId { get; }

        public PacketToken Token { get; }

        public PacketNumber Number { get; }

        public MemoryBuffer Payload { get; }

        public static bool TryParse(MemoryCursor cursor, out InitialPacket result)
        {
            result = new InitialPacket();

            var firstByte = PacketFirstByte.Parse(cursor.Peek(1).Span[0]);

            if (!firstByte.IsInitialType())
            {
                return false;
            }

            cursor.Move(1);

            var version = PacketVersion.Parse(cursor);
            var destinationConnectionId = PacketConnectionId.Parse(cursor);
            var sourceConnectionId = PacketConnectionId.Parse(cursor);
            var token = PacketToken.Parse(cursor);
            var packetBytes = PacketPayload.SlicePacketBytes(cursor);

            using (packetBytes.SetCursor(cursor))
            {
                var packetNumberBytes = firstByte.SlicePacketNumberBytes(cursor);
                var packetNumber = PacketNumber.Parse(packetNumberBytes);
                var payload = cursor.SliceToEnd();

                result = new InitialPacket(version,
                                           destinationConnectionId,
                                           sourceConnectionId,
                                           token,
                                           packetNumber,
                                           payload);
            }

            return true;
        }

        public static PacketPayload.CursorWritingContext StartWriting(MemoryCursor cursor,
                                                                      PacketVersion version,
                                                                      PacketConnectionId destinationConnectionId,
                                                                      PacketConnectionId sourceConnectionId,
                                                                      PacketNumber packetNumber,
                                                                      PacketToken token)
        {
            ref byte firstByte = ref cursor.Move(1).Span[0];

            version.WriteBytes(cursor);
            destinationConnectionId.WriteBytes(cursor);
            sourceConnectionId.WriteBytes(cursor);
            token.WriteBytes(cursor);

            var context = PacketPayload.StartPacketWriting(cursor);
            var lengthOfPacketNumber = packetNumber.Write(cursor);

            firstByte = new PacketFirstByte()
                .SetInitial()
                .SetPacketNumberLength(lengthOfPacketNumber)
                .Build();

            return context;
        }
    }
}
