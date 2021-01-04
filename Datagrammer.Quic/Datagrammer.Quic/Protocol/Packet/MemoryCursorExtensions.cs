using Datagrammer.Quic.Protocol.Error;

namespace Datagrammer.Quic.Protocol.Packet
{
    public static class MemoryCursorExtensions
    {
        public static void EncodeVariable(this MemoryCursor cursor, ulong value)
        {
            var bytes = cursor.PeekEnd();

            VariableLengthEncoding.Encode(bytes.Span, value, out var encodedLength);

            cursor.Move(encodedLength);
        }

        public static ulong DecodeVariable(this MemoryCursor cursor)
        {
            var bytes = cursor.PeekEnd();
            var value = VariableLengthEncoding.Decode(bytes.Span, out var encodedLength);

            cursor.Move(encodedLength);

            return value;
        }

        public static int DecodeVariable32(this MemoryCursor cursor)
        {
            var value = cursor.DecodeVariable();

            if (value > int.MaxValue)
            {
                throw new EncodingException();
            }

            return (int)value;
        }

        public static long DecodeVariable64(this MemoryCursor cursor)
        {
            var value = cursor.DecodeVariable();

            if (value > long.MaxValue)
            {
                throw new EncodingException();
            }

            return (long)value;
        }

        public static void EncodeVariable32(this MemoryCursor cursor, int value)
        {
            if (value < 0)
            {
                throw new EncodingException();
            }

            cursor.EncodeVariable((ulong)value);
        }

        public static void EncodeVariable64(this MemoryCursor cursor, long value)
        {
            if (value < 0)
            {
                throw new EncodingException();
            }

            cursor.EncodeVariable((ulong)value);
        }
    }
}
