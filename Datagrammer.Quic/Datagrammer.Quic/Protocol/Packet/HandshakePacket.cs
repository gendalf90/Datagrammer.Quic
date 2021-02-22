using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct HandshakePacket
    {
        private HandshakePacket(PacketVersion version,
                                PacketConnectionId destinationConnectionId,
                                PacketConnectionId sourceConnectionId,
                                PacketNumber number,
                                ReadOnlyMemory<byte> payload)
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

        public ReadOnlyMemory<byte> Payload { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out HandshakePacket result, out ReadOnlyMemory<byte> remainings)
        {
            result = new HandshakePacket();
            remainings = bytes;

            if (bytes.IsEmpty)
            {
                return false;
            }

            var firstByte = PacketFirstByte.Parse(bytes.Span[0]);

            if (!firstByte.IsHandshakeType())
            {
                return false;
            }

            var afterFirstByteBytes = bytes.Slice(1);
            var version = PacketVersion.Parse(afterFirstByteBytes, out var afterVersionBytes);
            var destinationConnectionId = PacketConnectionId.Parse(afterVersionBytes, out var afterDestinationConnectionIdBytes);
            var sourceConnectionId = PacketConnectionId.Parse(afterDestinationConnectionIdBytes, out var afterSourceConnectionIdBytes);
            var packetBytes = PacketPayload.SlicePacketBytes(afterSourceConnectionIdBytes, out var afterPacketBytes);
            var packetNumberBytes = firstByte.SlicePacketNumberBytes(packetBytes, out var afterPacketNumberBytes);
            var number = PacketNumber.Parse(packetNumberBytes.Span);

            remainings = afterPacketBytes;
            result = new HandshakePacket(version,
                                         destinationConnectionId,
                                         sourceConnectionId,
                                         number,
                                         afterPacketNumberBytes);

            return true;
        }
    }
}
