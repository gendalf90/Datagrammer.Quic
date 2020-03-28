using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct RttPacket
    {
        private RttPacket(PacketVersion version,
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

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out RttPacket result, out ReadOnlyMemory<byte> remainings)
        {
            result = new RttPacket();
            remainings = ReadOnlyMemory<byte>.Empty;

            var firstByte = PacketFirstByte.Parse(bytes, out var afterFirstByteBytes);

            if (firstByte.IsShortHeader())
            {
                return false;
            }

            if (!firstByte.IsRttType())
            {
                return false;
            }

            var version = PacketVersion.Parse(afterFirstByteBytes, out var afterVersionBytes);
            var destinationConnectionId = PacketConnectionId.Parse(afterVersionBytes, out var afterDestinationConnectionIdBytes);
            var sourceConnectionId = PacketConnectionId.Parse(afterDestinationConnectionIdBytes, out var afterSourceConnectionIdBytes);

            PacketLength.CheckPacketLength(afterSourceConnectionIdBytes, out var packetBytes, out var afterPacketBytes);

            var number = firstByte.ParseNumber(packetBytes, out var afterPacketNumberRemainings);

            remainings = afterPacketBytes;
            result = new RttPacket(version,
                                   destinationConnectionId,
                                   sourceConnectionId,
                                   number,
                                   afterPacketNumberRemainings);

            return true;
        }
    }
}
