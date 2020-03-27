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

        public static bool TryParseFrameType(ReadOnlyMemory<byte> bytes, out FrameType type, out ReadOnlyMemory<byte> remainings)
        {
            type = new FrameType();
            remainings = ReadOnlyMemory<byte>.Empty;

            if(!VariableLengthEncoding.TryDecode(bytes.Span, out var code, out var decodedLength))
            {
                return false;
            }

            if(code <= byte.MaxValue && decodedLength > 1)
            {
                return false;
            }

            if (code <= ushort.MaxValue && decodedLength > 2)
            {
                return false;
            }

            if (code <= uint.MaxValue && decodedLength > 4)
            {
                return false;
            }

            type = new FrameType(code);
            remainings = bytes.Slice(decodedLength);

            return true;
        }
    }
}
