using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public static class FrameType
    {
        public static bool TryParseFrameType(ReadOnlyMemory<byte> bytes, out ulong type, out ReadOnlyMemory<byte> remainings)
        {
            type = 0;
            remainings = ReadOnlyMemory<byte>.Empty;

            if(!VariableLengthEncoding.TryDecode(bytes.Span, out var value, out var decodedLength))
            {
                return false;
            }

            if(value <= byte.MaxValue && decodedLength > 1)
            {
                return false;
            }

            if (value <= ushort.MaxValue && decodedLength > 2)
            {
                return false;
            }

            if (value <= uint.MaxValue && decodedLength > 4)
            {
                return false;
            }

            type = value;
            remainings = bytes.Slice(decodedLength);

            return true;
        }
    }
}
