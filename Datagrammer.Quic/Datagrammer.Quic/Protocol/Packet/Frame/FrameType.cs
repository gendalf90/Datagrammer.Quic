using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct FrameType
    {
        private readonly ulong type;

        private FrameType(ulong type)
        {
            this.type = type;
        }

        public bool IsPadding() => type == 0;

        public bool IsPing() => type == 1;

        public bool IsAck() => type == 2 || type == 3;

        public bool HasAckEcnFeedback() => type == 3;

        public bool IsResetStream() => type == 4;

        public bool IsStopSending() => type == 5;

        public bool IsCrypto() => type == 6;

        public bool IsNewToken() => type == 7;

        public bool IsStream() => type >= 8 && type <= 15;

        public bool HasOffset() => Convert.ToBoolean((type >> 2) & 1);

        public bool HasLength() => Convert.ToBoolean((type >> 1) & 1);

        public bool HasFinal() => Convert.ToBoolean(type & 1);

        public bool IsMaxData() => type == 16;

        public bool IsMaxStreamData() => type == 17;

        public bool IsMaxStreams() => type == 18 || type == 19;

        public bool ForBidirectional() => type == 18 || type == 22;

        public bool ForUnidirectional() => type == 19 || type == 23;

        public bool IsDataBlocked() => type == 20;

        public bool IsStreamDataBlocked() => type == 21;

        public bool IsStreamsBlocked() => type == 22 || type == 23;

        public bool IsNewConnectionId() => type == 24;

        public static FrameType Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            remainings = ReadOnlyMemory<byte>.Empty;

            var code = VariableLengthEncoding.Decode(bytes.Span, out var decodedLength);

            if (code <= byte.MaxValue && decodedLength > 1)
            {
                throw new EncodingException();
            }

            if (code <= ushort.MaxValue && decodedLength > 2)
            {
                throw new EncodingException();
            }

            if (code <= uint.MaxValue && decodedLength > 4)
            {
                throw new EncodingException();
            }

            remainings = bytes.Slice(decodedLength);

            return new FrameType(code);
        }
    }
}
