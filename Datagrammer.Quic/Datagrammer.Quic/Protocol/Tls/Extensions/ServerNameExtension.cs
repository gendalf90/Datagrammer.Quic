using Datagrammer.Quic.Protocol.Error;
using System;
using System.Text;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct ServerNameExtension
    {
        private readonly ReadOnlyMemory<byte> bytes;

        private ServerNameExtension(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out ServerNameExtension result, out ReadOnlyMemory<byte> remainings)
        {
            result = new ServerNameExtension();
            remainings = bytes;

            var type = ExtensionType.Parse(bytes, out var afterTypeBytes);

            if (type != ExtensionType.ServerName)
            {
                return false;
            }

            var payload = ExtensionVectorPayload.Slice(afterTypeBytes, 0..ushort.MaxValue, out remainings);

            result = new ServerNameExtension(payload);

            return true;
        }

        public static void WriteHostName(ref Span<byte> destination, string hostName)
        {
            ExtensionType.ServerName.WriteBytes(ref destination);

            var context = ExtensionVectorPayload.StartWriting(ref destination, 0..ushort.MaxValue);

            WriteHostNameType(ref destination);
            WriteHostNameValue(ref destination, hostName);

            context.Complete(ref destination);
        }

        private static void WriteHostNameType(ref Span<byte> destination)
        {
            if(destination.IsEmpty)
            {
                throw new EncodingException();
            }

            destination[0] = 0;

            destination = destination.Slice(1);
        }

        private static void WriteHostNameValue(ref Span<byte> destination, string hostName)
        {
            var context = ByteVector.StartVectorWriting(ref destination, 0..ushort.MaxValue);

            try
            {
                var writtenBytes = Encoding.ASCII.GetBytes(hostName, destination);

                destination = destination.Slice(writtenBytes);
            }
            catch (Exception e)
            {
                throw new EncodingException("", e);
            }

            context.Complete(ref destination);
        }

        public void WriteBytes(ref Span<byte> destination)
        {
            ExtensionType.ServerName.WriteBytes(ref destination);

            var context = ExtensionVectorPayload.StartWriting(ref destination, 0..ushort.MaxValue);

            if (!bytes.Span.TryCopyTo(destination))
            {
                throw new EncodingException();
            }

            destination = destination.Slice(bytes.Length);

            context.Complete(ref destination);
        }

        public override string ToString()
        {
            return BitConverter.ToString(bytes.ToArray());
        }
    }
}
