using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Datagrammer.Quic.Protocol
{
    internal static class UnsafeBitConverter
    {
        public static short ToInt16(ReadOnlySpan<byte> value)
        {
            return Unsafe.ReadUnaligned<short>(ref MemoryMarshal.GetReference(value));
        }

        public static int ToInt32(ReadOnlySpan<byte> value)
        {
            return Unsafe.ReadUnaligned<int>(ref MemoryMarshal.GetReference(value));
        }

        public static long ToInt64(ReadOnlySpan<byte> value)
        {
            return Unsafe.ReadUnaligned<long>(ref MemoryMarshal.GetReference(value));
        }

        public static void WriteBytes(Span<byte> destination, short value)
        {
            if (destination.Length < sizeof(short))
            {
                throw new ArgumentOutOfRangeException(nameof(destination));
            }

            Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(destination), value);
        }

        public static void WriteBytes(Span<byte> destination, int value)
        {
            if (destination.Length < sizeof(int))
            {
                throw new ArgumentOutOfRangeException(nameof(destination));
            }

            Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(destination), value);
        }
    }
}
