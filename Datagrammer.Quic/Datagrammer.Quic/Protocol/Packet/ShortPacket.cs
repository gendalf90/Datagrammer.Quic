using Datagrammer.Quic.Protocol.Tls;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct ShortPacket
    {
        private ShortPacket(PacketConnectionId destinationConnectionId,
                            PacketNumber number,
                            MemoryBuffer payload)
        {
            DestinationConnectionId = destinationConnectionId;
            Number = number;
            Payload = payload;
        }

        public PacketConnectionId DestinationConnectionId { get; }

        public PacketNumber Number { get; }

        public MemoryBuffer Payload { get; }

        public static bool TryParseProtectedByConnectionId(IAead aead,
                                                           ICipher cipher,
                                                           MemoryCursor cursor, 
                                                           PacketConnectionId connectionId,
                                                           PacketNumber largestAcknowledgedPacketNumber,
                                                           out ShortPacket result)
        {
            result = new ShortPacket();

            var startOffset = cursor.AsOffset();
            var firstByte = PacketFirstByte.Parse(cursor.Peek(1).Span[0]);

            if (!firstByte.IsShortHeader())
            {
                return false;
            }

            cursor.Move(1);

            if (!connectionId.TrySliceValue(cursor))
            {
                return false;
            }

            var payload = PacketPayload.SliceShortProtectedPacketBytes(cursor, aead, cipher, startOffset, firstByte, largestAcknowledgedPacketNumber, out var packetNumber);

            result = new ShortPacket(connectionId, packetNumber, payload);

            return true;
        }

        public static PacketPayload.ShortProtectedWritingContext StartProtectedWriting(IAead aead,
                                                                                       ICipher cipher,
                                                                                       MemoryCursor cursor,
                                                                                       PacketConnectionId destinationConnectionId,
                                                                                       PacketNumber packetNumber,
                                                                                       PacketNumber largestAcknowledgedPacketNumber)
        {
            var startOffset = cursor.AsOffset();
            var firstByte = new PacketFirstByte().SetShort();

            firstByte.Write(cursor);
            destinationConnectionId.WriteValueBytes(cursor);

            return PacketPayload.StartShortProtectedPacketWriting(cursor, aead, cipher, startOffset, firstByte, packetNumber, largestAcknowledgedPacketNumber);
        }
    }
}
