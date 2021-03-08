using Datagrammer.Quic.Protocol.Tls;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct RttPacket
    {
        private RttPacket(PacketVersion version,
                          PacketConnectionId destinationConnectionId,
                          PacketConnectionId sourceConnectionId,
                          PacketNumber number,
                          MemoryBuffer payload)
        {
            Version = version;
            DestinationConnectionId = destinationConnectionId;
            SourceConnectionId = sourceConnectionId;
            Number = number;
            Payload = payload;
        }

        public PacketVersion Version { get; }

        public PacketConnectionId DestinationConnectionId { get; }

        public PacketConnectionId SourceConnectionId { get; }

        public PacketNumber Number { get; }

        public MemoryBuffer Payload { get; }

        public static bool TryParse(MemoryCursor cursor, PacketNumber largestAcknowledgedPacketNumber, out RttPacket result)
        {
            result = new RttPacket();

            var startOffset = cursor.AsOffset();
            var firstByte = PacketFirstByte.Parse(cursor.Peek(1).Span[0]);

            if (!firstByte.IsHandshakeType())
            {
                return false;
            }

            cursor.Move(1);

            var version = PacketVersion.Parse(cursor);
            var destinationConnectionId = PacketConnectionId.Parse(cursor);
            var sourceConnectionId = PacketConnectionId.Parse(cursor);
            var payload = PacketPayload.SlicePacketBytes(cursor, firstByte, startOffset, largestAcknowledgedPacketNumber, out var packetNumber);

            result = new RttPacket(version,
                                   destinationConnectionId,
                                   sourceConnectionId,
                                   packetNumber,
                                   payload);

            return true;
        }

        public static bool TryParseProtected(IAead aead, ICipher cipher, MemoryCursor cursor, PacketNumber largestAcknowledgedPacketNumber, out RttPacket result)
        {
            result = new RttPacket();

            var startOffset = cursor.AsOffset();
            var firstByte = PacketFirstByte.Parse(cursor.Peek(1).Span[0]);

            if (!firstByte.IsHandshakeType())
            {
                return false;
            }

            cursor.Move(1);

            var version = PacketVersion.Parse(cursor);
            var destinationConnectionId = PacketConnectionId.Parse(cursor);
            var sourceConnectionId = PacketConnectionId.Parse(cursor);
            var payload = PacketPayload.SliceLongProtectedPacketBytes(cursor, aead, cipher, startOffset, firstByte, largestAcknowledgedPacketNumber, out var packetNumber);

            result = new RttPacket(version,
                                   destinationConnectionId,
                                   sourceConnectionId,
                                   packetNumber,
                                   payload);

            return true;
        }

        public static PacketPayload.CursorWritingContext StartWriting(MemoryCursor cursor,
                                                                      PacketVersion version,
                                                                      PacketConnectionId destinationConnectionId,
                                                                      PacketConnectionId sourceConnectionId,
                                                                      PacketNumber largestAcknowledgedPacketNumber,
                                                                      PacketNumber packetNumber)
        {
            var startOffset = cursor.AsOffset();
            var firstByte = new PacketFirstByte()
                .SetRtt()
                .SetMaxPacketNumberLength();

            firstByte.Write(cursor);
            version.WriteBytes(cursor);
            destinationConnectionId.WriteBytes(cursor);
            sourceConnectionId.WriteBytes(cursor);

            var context = PacketPayload.StartPacketWriting(cursor, startOffset);
            var packetNumberBytes = firstByte.SlicePacketNumberBytes(cursor);

            packetNumber
                .EncodeByLargestAcknowledged(largestAcknowledgedPacketNumber)
                .Fill(packetNumberBytes.Span);

            return context;
        }

        public static PacketPayload.LongProtectedWritingContext StartProtectedWriting(IAead aead,
                                                                                      ICipher cipher,
                                                                                      MemoryCursor cursor,
                                                                                      PacketVersion version,
                                                                                      PacketConnectionId destinationConnectionId,
                                                                                      PacketConnectionId sourceConnectionId,
                                                                                      PacketNumber packetNumber,
                                                                                      PacketNumber largestAcknowledgedPacketNumber)
        {
            var startPacketOffset = cursor.AsOffset();
            var firstByte = new PacketFirstByte()
                .SetRtt()
                .SetMaxPacketNumberLength();

            firstByte.Write(cursor);
            version.WriteBytes(cursor);
            destinationConnectionId.WriteBytes(cursor);
            sourceConnectionId.WriteBytes(cursor);

            return PacketPayload.StartLongProtectedPacketWriting(cursor, aead, cipher, startPacketOffset, firstByte, packetNumber, largestAcknowledgedPacketNumber);
        }
    }
}
