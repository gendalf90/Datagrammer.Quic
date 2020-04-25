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

            if(bytes.IsEmpty)
            {
                return false;
            }

            var firstByte = PacketFirstByte.Parse(bytes, out var afterFirstByteBytes);

            if(!firstByte.IsInitialType())
            {
                return false;
            }

            var version = PacketVersion.Parse(afterFirstByteBytes, out var afterVersionBytes);
            var destinationConnectionId = PacketConnectionId.Parse(afterVersionBytes, out var afterDestinationConnectionIdBytes);
            var sourceConnectionId = PacketConnectionId.Parse(afterDestinationConnectionIdBytes, out var afterSourceConnectionIdBytes);
            var token = PacketToken.Parse(afterSourceConnectionIdBytes, out var afterTokenBytes);
            var packetBytes = PacketLength.SlicePacketBytes(afterTokenBytes, out var afterPacketBytes);
            var packetNumberBytes = firstByte.SlicePacketNumberBytes(packetBytes, out var afterPacketNumberBytes);
            var number = PacketNumber.Parse(packetNumberBytes);

            remainings = afterPacketBytes;
            result = new InitialPacket(version,
                                       destinationConnectionId,
                                       sourceConnectionId,
                                       token,
                                       number,
                                       afterPacketNumberBytes);

            return true;
        }

        public void WriteBytes(Span<byte> bytes, out Span<byte> remainings)
        {
            remainings = bytes;

            new PacketFirstByte()
                .SetInitial()
                .SetPacketNumber(Number)
                .WriteBytes(remainings, out remainings);

            Version.WriteBytes(remainings, out remainings);
            DestinationConnectionId.WriteBytes(remainings, out remainings);
            SourceConnectionId.WriteBytes(remainings, out remainings);
            Token.WriteBytes(remainings, out remainings);
            PacketLength.WritePacketBytes(remainings, Number, Payload, out remainings);
        }
    }
}
