using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct NewConnectionIdFrame
    {
        private NewConnectionIdFrame(int sequenceNumber,
                                     int sequenceNumberToRetire,
                                     PacketConnectionId connectionId,
                                     PacketToken resetToken)
        {
            SequenceNumber = sequenceNumber;
            SequenceNumberToRetire = sequenceNumberToRetire;
            ConnectionId = connectionId;
            ResetToken = resetToken;
        }

        public int SequenceNumber { get; }

        public int SequenceNumberToRetire { get; }

        public PacketConnectionId ConnectionId { get; }

        public PacketToken ResetToken { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out NewConnectionIdFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new NewConnectionIdFrame();
            remainings = ReadOnlyMemory<byte>.Empty;

            var type = FrameType.Parse(bytes, out var afterTypeBytes);

            if (!type.IsNewConnectionId())
            {
                return false;
            }

            var sequenceNumber = VariableLengthEncoding.Decode32(afterTypeBytes.Span, out var decodedLength);
            var afterSequenceNumberBytes = afterTypeBytes.Slice(decodedLength);
            var sequenceNumberToRetire = VariableLengthEncoding.Decode32(afterSequenceNumberBytes.Span, out decodedLength);
            var afterSequenceNumberToRetiryBytes = afterSequenceNumberBytes.Slice(decodedLength);

            if (sequenceNumberToRetire > sequenceNumber)
            {
                throw new EncodingException();
            }

            var connectionId = PacketConnectionId.Parse(afterSequenceNumberToRetiryBytes, out var afterConnectionIdBytes);
            var resetToken = ParseResetToken(afterConnectionIdBytes, out var afterTokenBytes);

            result = new NewConnectionIdFrame(sequenceNumber, sequenceNumberToRetire, connectionId, resetToken);
            remainings = afterTokenBytes;

            return true;
        }

        private static PacketToken ParseResetToken(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            remainings = ReadOnlyMemory<byte>.Empty;

            if (bytes.Length < 16)
            {
                throw new EncodingException();
            }

            var tokenBytes = bytes.Slice(0, 16);

            remainings = bytes.Slice(16);

            return new PacketToken(tokenBytes);
        }
    }
}
