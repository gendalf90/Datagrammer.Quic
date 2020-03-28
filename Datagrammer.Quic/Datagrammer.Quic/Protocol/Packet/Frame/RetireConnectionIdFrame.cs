using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct RetireConnectionIdFrame
    {
        private RetireConnectionIdFrame(int sequenceNumber)
        {
            SequenceNumber = sequenceNumber;
        }

        public int SequenceNumber { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out RetireConnectionIdFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new RetireConnectionIdFrame();
            remainings = ReadOnlyMemory<byte>.Empty;

            var type = FrameType.Parse(bytes, out var afterTypeBytes);

            if (!type.IsRetireConnectionId())
            {
                return false;
            }

            var sequenceNumber = VariableLengthEncoding.Decode32(afterTypeBytes.Span, out var decodedLength);
            var afterSequenceNumberBytes = afterTypeBytes.Slice(decodedLength);

            result = new RetireConnectionIdFrame(sequenceNumber);
            remainings = afterSequenceNumberBytes;

            return true;
        }
    }
}
