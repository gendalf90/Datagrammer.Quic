using Datagrammer.Quic.Protocol.Error;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct CipherSuite
    {
        private readonly ReadOnlyMemory<byte> bytes;
        private readonly bool isList;

        private CipherSuite(ReadOnlyMemory<byte> bytes, bool isList)
        {
            this.bytes = bytes;
            this.isList = isList;
        }

        public static CipherSuite CreateFromList(IEnumerable<Cipher> ciphers)
        {
            using (var stream = new MemoryStream())
            {
                foreach (var cipher in ciphers)
                {
                    cipher.WriteBytes(stream);
                }

                return new CipherSuite(stream.ToArray(), true);
            }
        }

        public bool TrySelectOneCipherFromList(IEnumerable<Cipher> ciphers, out CipherSuite result)
        {
            var remainings = bytes;
            
            while (TryParseOneCipher(remainings, out var cipher, out result, out remainings))
            {
                if(ciphers.Contains(cipher))
                {
                    return true;
                }
            }
            
            return false;
        }

        private bool TryParseOneCipher(ReadOnlyMemory<byte> data, out Cipher cipher, out CipherSuite suite, out ReadOnlyMemory<byte> remainings)
        {
            cipher = new Cipher();
            suite = new CipherSuite();
            remainings = data;

            if(data.IsEmpty)
            {
                return false;
            }

            cipher = Cipher.Parse(data, out remainings);
            suite = new CipherSuite(data.Slice(0, data.Length - remainings.Length), false);

            return true;
        }

        public bool HasAnyFrom(IEnumerable<Cipher> ciphers)
        {
            return TrySelectOneCipherFromList(ciphers, out _);
        }

        public static CipherSuite ParseList(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var data = ByteVector.SliceVectorBytes(bytes, 2..ushort.MaxValue, out remainings);

            return new CipherSuite(data, true);
        }

        public static CipherSuite ParseOne(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            Cipher.Parse(bytes, out remainings);

            return new CipherSuite(bytes.Slice(0, bytes.Length - remainings.Length), false);
        }

        public void Write(ref Span<byte> destination)
        {
            if(isList)
            {
                WriteVector(ref destination);
            }
            else
            {
                WriteBytes(ref destination);
            }
        }

        private void WriteBytes(ref Span<byte> destination)
        {
            if (!bytes.Span.TryCopyTo(destination))
            {
                throw new EncodingException();
            }

            destination = destination.Slice(bytes.Length);
        }

        private void WriteVector(ref Span<byte> destination)
        {
            var vectorContext = ByteVector.StartVectorWriting(ref destination, 2..ushort.MaxValue);

            WriteBytes(ref destination);

            vectorContext.Complete(ref destination);
        }

        public override string ToString()
        {
            return BitConverter.ToString(bytes.ToArray());
        }
    }
}
