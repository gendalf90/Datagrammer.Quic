using System;
using System.Net;

namespace Datagrammer.Quic
{
    internal static class NetworkBitConverter
    {
        public static short ToInt16(ReadOnlySpan<byte> bytes)
        {
            return IPAddress.NetworkToHostOrder(UnsafeBitConverter.ToInt16(bytes));
        }

        public static ushort ToUInt16(ReadOnlySpan<byte> bytes)
        {
            return unchecked((ushort)ToInt16(bytes));
        }

        public static int ToInt32(ReadOnlySpan<byte> bytes)
        {
            return IPAddress.NetworkToHostOrder(UnsafeBitConverter.ToInt32(bytes));
        }

        public static uint ToUInt32(ReadOnlySpan<byte> bytes)
        {
            return unchecked((uint)ToInt32(bytes));
        }

        public static long ToInt64(ReadOnlySpan<byte> bytes)
        {
            return IPAddress.NetworkToHostOrder(UnsafeBitConverter.ToInt64(bytes));
        }

        public static ulong ToUInt64(ReadOnlySpan<byte> bytes)
        {
            return unchecked((ulong)ToInt64(bytes));
        }

        public static void WriteBytes(Span<byte> destination, short value)
        {
            UnsafeBitConverter.WriteBytes(destination, IPAddress.HostToNetworkOrder(value));
        }

        public static void WriteBytes(Span<byte> destination, ushort value)
        {
            WriteBytes(destination, unchecked((short)value));
        }

        public static void WriteBytes(Span<byte> destination, int value)
        {
            UnsafeBitConverter.WriteBytes(destination, IPAddress.HostToNetworkOrder(value));
        }
    }
}
