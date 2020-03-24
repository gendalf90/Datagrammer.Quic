using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct InitialPacket
    {
        private InitialPacket(PacketVersion version,
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
            remainings = ReadOnlyMemory<byte>.Empty;

            if(!PacketFirstByte.TryParse(bytes, out var firstByte, out var afterFirstByteBytes))
            {
                return false;
            }

            if(firstByte.IsShortHeader())
            {
                return false;
            }

            if(!firstByte.IsInitialType())
            {
                return false;
            }

            if(!PacketVersion.TryParse(afterFirstByteBytes, out var version, out var afterVersionBytes))
            {
                return false;
            }

            if(!PacketConnectionId.TryParse(afterVersionBytes, out var destinationConnectionId, out var afterDestinationConnectionIdBytes))
            {
                return false;
            }

            if (!PacketConnectionId.TryParse(afterDestinationConnectionIdBytes, out var sourceConnectionId, out var afterSourceConnectionIdBytes))
            {
                return false;
            }

            if(!PacketToken.TryParse(afterSourceConnectionIdBytes, out var token, out var afterTokenBytes))
            {
                return false;
            }

            if(!PacketLength.CheckPacketLength(afterTokenBytes, out var packetBytes, out var afterPacketBytes))
            {
                return false;
            }

            if(!firstByte.TryParseNumber(packetBytes, out var number, out var afterPacketNumberRemainings))
            {
                return false;
            }

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
