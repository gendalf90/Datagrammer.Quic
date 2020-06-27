using Datagrammer;
using Datagrammer.Quic.Protocol.Packet;
using Datagrammer.Quic.Protocol.Packet.Frame;
using Datagrammer.Quic.Protocol.Tls;
using Datagrammer.Quic.Protocol.Tls.Extensions;
using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using Xunit;

namespace Tests
{
    public class UnitTest1
    {
        [Fact]
        public void Test1()
        {
            var bytes = GetData();

            InitialPacket.TryParse(bytes, out var initial, out var remainings);

            CryptoFrame.TryParse(initial.Payload, out var crypto, out var afterCrypto);

            ClientHello.TryParse(crypto.Data, out var hello, out var afterHello);

            KeyShareExtension.TryParse(hello.Payload, out var keyShare, out var afterKeyShare);

            var unknownBytes = UnknownExtension.SliceBytes(afterKeyShare, out var afterUnknown);

            AlpnExtension.TryParse(afterUnknown, out var alpn, out var afterAlpn);

            SupportedVersionExtension.TryParse(afterAlpn, out var supportedVersion, out var afterSupportedVersion);

            SignatureAlgorithmsExtension.TryParse(afterSupportedVersion, out var signatureAlgorithms, out var afterSignatureAlgorithms);

            SupportedGroupsExtension.TryParse(afterSignatureAlgorithms, out var supportedGroups, out var afterSupportedGroups);

            TransportParametersExtension.TryParse(afterSupportedGroups, out var transportParametersExtension, out var afterTransportParametersExtension);

            PskKeyExchangeModesExtension.TryParse(afterTransportParametersExtension, out var pskKeyExchangeModes, out var afterPsk);

            //----------------------------------------------------------------

            var buffer = new byte[65000];
            var destination = buffer.AsSpan();

            var initialContext = InitialPacket.StartWriting(ref destination, initial.Version, initial.DestinationConnectionId, initial.SourceConnectionId, initial.Number, initial.Token);
            var cryptoContext = CryptoFrame.StartWriting(ref destination, 0);
            var clientHelloContext = ClientHello.StartWriting(ref destination, hello.Random, hello.CipherSuite, hello.SessionId);

            keyShare.WriteBytes(ref destination);

            unknownBytes.Span.CopyTo(destination);
            destination = destination.Slice(unknownBytes.Length);

            alpn.WriteBytes(ref destination);

            supportedVersion.WriteBytes(ref destination);

            signatureAlgorithms.WriteBytes(ref destination);

            supportedGroups.WriteBytes(ref destination);

            var transportParametersContext = TransportParametersExtension.StartWriting(ref destination);
            transportParametersExtension.Data.Span.CopyTo(destination);
            destination = destination.Slice(transportParametersExtension.Data.Length);
            transportParametersContext.Complete(ref destination);

            pskKeyExchangeModes.WriteBytes(ref destination);

            clientHelloContext.Complete(ref destination);
            cryptoContext.Complete(ref destination);

            for (int i = 0; i < 1000; i++)
            {
                PaddingFrame.WriteBytes(ref destination);
            }

            initialContext.Complete(ref destination);

            //----------------------------------------------------------------

            InitialPacket.TryParse(buffer.ToArray(), out var initial1, out var remainings1);

            CryptoFrame.TryParse(initial1.Payload, out var crypto1, out var afterCrypto1);

            ClientHello.TryParse(crypto1.Data, out var hello1, out var afterHello1);

            KeyShareExtension.TryParse(hello1.Payload, out var keyShare1, out var afterKeyShare1);

            var unknownBytes1 = UnknownExtension.SliceBytes(afterKeyShare1, out var afterUnknown1);

            AlpnExtension.TryParse(afterUnknown1, out var alpn1, out var afterAlpn1);

            SupportedVersionExtension.TryParse(afterAlpn1, out var supportedVersion1, out var afterSupportedVersion1);

            SignatureAlgorithmsExtension.TryParse(afterSupportedVersion1, out var signatureAlgorithms1, out var afterSignatureAlgorithms1);

            SupportedGroupsExtension.TryParse(afterSignatureAlgorithms1, out var supportedGroups1, out var afterSupportedGroups1);

            TransportParametersExtension.TryParse(afterSupportedGroups1, out var transportParametersExtension1, out var afterTransportParametersExtension1);

            PskKeyExchangeModesExtension.TryParse(afterTransportParametersExtension1, out var pskKeyExchangeModes1, out var afterPsk1);

            var client = DatagramChannel.Start(opt =>
            {
                opt.ListeningPoint = new IPEndPoint(IPAddress.Any, 50000);
            });

            var addr = Dns.GetHostAddresses("litespeedtech.com"); //443
            //var addr = Dns.GetHostAddresses("test.privateoctopus.com"); //4433
            //var addr = Dns.GetHostAddresses("quant.eggert.org"); //4433
            //var addr = Dns.GetHostAddresses("f5quic.com"); //4433

            var dgram = new Datagram().WithAddress(addr[0]).WithPort(443).WithBuffer(buffer.ToArray());

            client.Writer.TryWrite(dgram);

            var response = client.Reader.ReadAsync().AsTask().Result;
        }

        static byte[] GetData()
        {
            return File
                .ReadAllText("c:\\test CH 1.txt")
                .Split(new string[] { " ", Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries)
                .Select(bStr => byte.Parse(bStr, NumberStyles.HexNumber))
                .ToArray();
        }
    }
}
