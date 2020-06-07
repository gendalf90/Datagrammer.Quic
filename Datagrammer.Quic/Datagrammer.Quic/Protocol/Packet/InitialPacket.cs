using Datagrammer.Quic.Protocol.Error;
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
            remainings = bytes;

            if(bytes.IsEmpty)
            {
                return false;
            }

            var firstByte = PacketFirstByte.Parse(bytes.Span[0]);

            if (!firstByte.IsInitialType())
            {
                return false;
            }

            var afterFirstByteBytes = bytes.Slice(1);
            var version = PacketVersion.Parse(afterFirstByteBytes, out var afterVersionBytes);
            var destinationConnectionId = PacketConnectionId.Parse(afterVersionBytes, out var afterDestinationConnectionIdBytes);
            var sourceConnectionId = PacketConnectionId.Parse(afterDestinationConnectionIdBytes, out var afterSourceConnectionIdBytes);
            var token = PacketToken.Parse(afterSourceConnectionIdBytes, out var afterTokenBytes);
            var packetBytes = PacketPayload.SlicePacketBytes(afterTokenBytes, out var afterPacketBytes);
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

        public static PacketPayload.WritingContext StartWriting(Span<byte> destination,
                                                                PacketVersion version,
                                                                PacketConnectionId destinationConnectionId,
                                                                PacketConnectionId sourceConnectionId,
                                                                PacketNumber number,
                                                                PacketToken token)
        {
            if(destination.IsEmpty)
            {
                throw new EncodingException();
            }

            var remainings = destination.Slice(1);

            version.WriteBytes(remainings, out remainings);
            destinationConnectionId.WriteBytes(remainings, out remainings);
            sourceConnectionId.WriteBytes(remainings, out remainings);
            token.WriteBytes(remainings, out remainings);

            var context = PacketPayload.StartPacketWriting(remainings);
            var lengthOfNumber = number.Write(context.Cursor.Destination);

            context.Cursor = context.Cursor.Move(lengthOfNumber);
            destination[0] = new PacketFirstByte()
                .SetInitial()
                .SetPacketNumberLength(lengthOfNumber)
                .Build();
            
            return context;
        }
    }
}
