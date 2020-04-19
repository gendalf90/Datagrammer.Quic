using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct InitialPacket
    {
        public InitialPacket(PacketVersion version,
                             PacketConnectionId destinationConnectionId,
                             PacketConnectionId sourceConnectionId,
                             PacketToken token,
                             PacketNumber number,
                             ReadOnlyMemory<byte> payload)
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

        public ReadOnlyMemory<byte> Payload { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out InitialPacket result, out ReadOnlyMemory<byte> remainings)
        {
            result = new InitialPacket();
            remainings = bytes;

            var firstByte = PacketFirstByte.Parse(bytes, out var afterFirstByteBytes);

            if(firstByte.IsShortHeader())
            {
                return false;
            }

            if(!firstByte.IsInitialType())
            {
                return false;
            }

            var version = PacketVersion.Parse(afterFirstByteBytes, out var afterVersionBytes);
            var destinationConnectionId = PacketConnectionId.Parse(afterVersionBytes, out var afterDestinationConnectionIdBytes);
            var sourceConnectionId = PacketConnectionId.Parse(afterDestinationConnectionIdBytes, out var afterSourceConnectionIdBytes);
            var token = PacketToken.Parse(afterSourceConnectionIdBytes, out var afterTokenBytes);

            PacketLength.CheckPacketLength(afterTokenBytes, out var packetBytes, out var afterPacketBytes);

            var number = firstByte.ParseNumber(packetBytes, out var afterPacketNumberRemainings);

            remainings = afterPacketBytes;
            result = new InitialPacket(version,
                                       destinationConnectionId,
                                       sourceConnectionId,
                                       token,
                                       number,
                                       afterPacketNumberRemainings);

            return true;
        }
    }
}
