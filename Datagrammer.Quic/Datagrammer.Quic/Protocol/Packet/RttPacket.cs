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

            if (!PacketFirstByte.TryParse(bytes, out var firstByte, out var afterFirstByteBytes))
            {
                return false;
            }

            if (firstByte.IsShortHeader())
            {
                return false;
            }

            if (!firstByte.IsRttType())
            {
                return false;
            }

            if (!PacketVersion.TryParse(afterFirstByteBytes, out var version, out var afterVersionBytes))
            {
                return false;
            }

            if (!PacketConnectionId.TryParse(afterVersionBytes, out var destinationConnectionId, out var afterDestinationConnectionIdBytes))
            {
                return false;
            }

            if (!PacketConnectionId.TryParse(afterDestinationConnectionIdBytes, out var sourceConnectionId, out var afterSourceConnectionIdBytes))
            {
                return false;
            }

            if (!PacketLength.CheckPacketLength(afterSourceConnectionIdBytes, out var packetBytes, out var afterPacketBytes))
            {
                return false;
            }

            if (!firstByte.TryParseNumber(packetBytes, out var number, out var afterPacketNumberRemainings))
            {
                return false;
            }

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
