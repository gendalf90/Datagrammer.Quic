using Datagrammer.Quic.Protocol.Tls;

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

            var startOffset = cursor.AsOffset();
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
            var payload = PacketPayload.SlicePacketBytes(cursor, firstByte, startOffset, null, out var packetNumber);

            result = new InitialPacket(version,
                                       destinationConnectionId,
                                       sourceConnectionId,
                                       token,
                                       packetNumber,
                                       payload);

            return true;
        }

        public static bool TryParseProtected(IAead aead, ICipher cipher, MemoryCursor cursor, out InitialPacket result)
        {
            result = new InitialPacket();

            var startOffset = cursor.AsOffset();
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
            var payload = PacketPayload.SliceLongProtectedPacketBytes(cursor, aead, cipher, startOffset, firstByte, null, out var packetNumber);

            result = new InitialPacket(version,
                                       destinationConnectionId,
                                       sourceConnectionId,
                                       token,
                                       packetNumber,
                                       payload);

            return true;
        }

        public static PacketPayload.CursorWritingContext StartWriting(MemoryCursor cursor,
                                                                      PacketVersion version,
                                                                      PacketConnectionId destinationConnectionId,
                                                                      PacketConnectionId sourceConnectionId,
                                                                      PacketNumber packetNumber,
                                                                      PacketToken token)
        {
            var startOffset = cursor.AsOffset();
            var firstByte = new PacketFirstByte()
                .SetInitial()
                .SetMaxPacketNumberLength();

            firstByte.Write(cursor);
            version.WriteBytes(cursor);
            destinationConnectionId.WriteBytes(cursor);
            sourceConnectionId.WriteBytes(cursor);
            token.WriteBytes(cursor);

            var context = PacketPayload.StartPacketWriting(cursor, startOffset);
            var packetNumberBytes = firstByte.SlicePacketNumberBytes(cursor);

            packetNumber.Fill(packetNumberBytes.Span);

            return context;
        }

        public static PacketPayload.LongProtectedWritingContext StartProtectedWriting(IAead aead,
                                                                                      ICipher cipher,
                                                                                      MemoryCursor cursor,
                                                                                      PacketVersion version,
                                                                                      PacketConnectionId destinationConnectionId,
                                                                                      PacketConnectionId sourceConnectionId,
                                                                                      PacketNumber packetNumber,
                                                                                      PacketToken token)
        {
            var startPacketOffset = cursor.AsOffset();
            var firstByte = new PacketFirstByte()
                .SetInitial()
                .SetMaxPacketNumberLength();

            firstByte.Write(cursor);
            version.WriteBytes(cursor);
            destinationConnectionId.WriteBytes(cursor);
            sourceConnectionId.WriteBytes(cursor);
            token.WriteBytes(cursor);

            return PacketPayload.StartLongProtectedPacketWriting(cursor, aead, cipher, startPacketOffset, firstByte, packetNumber, null);
        }
    }
}
