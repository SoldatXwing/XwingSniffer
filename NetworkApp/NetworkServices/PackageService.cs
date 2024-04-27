using PacketDotNet;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetworkApp.NetworkServices
{
    public static class PackageService
    {
        private static readonly List<string> blockList = new List<string> { "31", "192", "75", "10", "162", "73" };
        private static List<PackageInformation> _capturedPackets = new List<PackageInformation>();

        public static void Device_OnPacketArrival(object sender, PacketCapture e)
        {
            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            var ipPacket = packet.Extract<IPv4Packet>();

            if (ipPacket is not null)
            {
                string srcIp = ipPacket.SourceAddress.ToString();

                if (!blockList.Contains(srcIp.Split('.')[0])
                    && ipPacket.Protocol == ProtocolType.Udp
                    && !_capturedPackets.Any(c => c.Ip == srcIp))
                {
                    string geoDataFormated = GetGeoInfo(srcIp).Result;
                    Console.WriteLine(geoDataFormated);
                }
            }
        }
        private static async Task<string> GetGeoInfo(string ip)
        {
            using (HttpClient client = new HttpClient())
            {
                var response = await client.GetAsync($"http://ip-api.com/json/{ip}");
                if (response.IsSuccessStatusCode)
                {
                    PackageInformation responsePackage = Newtonsoft.Json.JsonConvert.DeserializeObject<PackageInformation>(await response.Content.ReadAsStringAsync());
                    responsePackage.Ip = ip;
                    _capturedPackets.Add(responsePackage);
                    return $"Country: {responsePackage.Country} \n" +
                            $"RegionName: {responsePackage.Regionname} \n" +
                            $"City: {responsePackage.City} \n" +
                            $"PostCode: {responsePackage.Zip}\n" +
                            $"Lat: {responsePackage.Lat} \n" +
                            $"Lon {responsePackage.Lon}  \n" +
                            $"Ip: {ip} \n" +
                            $"Org: {responsePackage.Org}\n" +
                            $"Isp: {responsePackage.Isp}\n";

                }
                return "";
            }
        }
        public static void ClearIps() => _capturedPackets.Clear();
        public static List<PackageInformation> GetIps() => _capturedPackets;
    }
}
