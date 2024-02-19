using PacketDotNet;
using SharpPcap;
using System.Security.Cryptography;
public class Program
{
    private static ICaptureDevice device = CaptureDeviceList.Instance.FirstOrDefault();
    private static readonly List<string> blockList = new List<string> { "31", "192", "75", "10", "162", "73" };
    private static List<PackageInformation> _capturedPackets = new List<PackageInformation>();
    public static void Main(string[] args)
    {
        Console.Title = "Xwing Sniffer";
        bool run = true;
        ShowSniffer();
        while (run)
        {

            device.OnPacketArrival += Device_OnPacketArrival;
            device.Open(SharpPcap.DeviceModes.Promiscuous);
            device.StartCapture();

            var currentKey = Console.ReadKey();
            if (currentKey.KeyChar is 'e' || currentKey.KeyChar is 'E')
                run = false;
            else if (currentKey.KeyChar is 'i' || currentKey.KeyChar is 'I')
            {
                device.StopCapture();
                ShowInterfaceMenu();
                ShowSniffer();
            }
            else if (currentKey.KeyChar is 'c' || currentKey.KeyChar is 'C')
            {
                _capturedPackets.Clear();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\nIps cleared!");
                Console.ForegroundColor = ConsoleColor.White;
            }
            else if (currentKey.KeyChar is 's' || currentKey.KeyChar is 'S')
            {
                device.StopCapture();
                DisplayCapturedPackages();
                ShowSniffer();
            }
        }
        device.StopCapture();
        device.Close();
    }
    private static void DisplayCapturedPackages()
    {
        bool repeat;
        string txtContent = string.Empty;
        do
        {
            repeat = true;
            Console.Clear();
            foreach (var package in _capturedPackets)
            {
                string information = $"Country: {package.Country} \n" +
                            $"RegionName: {package.Regionname} \n" +
                            $"City: {package.City} \n" +
                            $"PostCode: {package.Zip}\n" +
                            $"Lat: {package.Lat} \n" +
                            $"Lon {package.Lon}  \n" +
                            $"Ip: {package.Ip} \n" +
                            $"Org: {package.Org}\n" +
                            $"Isp: {package.Isp}\n" +
                            $"------------------\n";
                Console.WriteLine(information);
                txtContent = txtContent + information;
            }
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("[S] Save information to txt file (saved under Documents)\n[E] Exit");
            Console.ForegroundColor = ConsoleColor.White;
            var key = Console.ReadKey();
            if (key.KeyChar is 'S' || key.KeyChar is 's')
            {
                Directory.CreateDirectory(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + "\\XwingSniffer");
                File.WriteAllText(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + "\\XwingSniffer\\CapturedPackages.txt", txtContent);
                repeat = false;
            }
            else if (key.KeyChar is 'E' || key.KeyChar is 'e')
                repeat = false;

            Console.Clear();

        } while (repeat);


    }
    private static void ShowSniffer()
    {
        if (device == null)
        {
            Console.WriteLine("No capture devices found.");
            return;
        }
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("____  ___       .__                            \r\n\\   \\/  /_  _  _|__| ____    ____              \r\n \\     /\\ \\/ \\/ /  |/    \\  / ___\\             \r\n /     \\ \\     /|  |   |  \\/ /_/  >            \r\n/___/\\  \\ \\/\\_/ |__|___|  /\\___  /             \r\n      \\_/               \\//_____/              \r\n  _________      .__  _____  _____             \r\n /   _____/ ____ |__|/ ____\\/ ____\\___________ \r\n \\_____  \\ /    \\|  \\   __\\\\   __\\/ __ \\_  __ \\\r\n /        \\   |  \\  ||  |   |  | \\  ___/|  | \\/\r\n/_______  /___|  /__||__|   |__|  \\___  >__|   \r\n        \\/     \\/                     \\/       "); //Xwing Sniffer
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("Currently sniffing on: " + device.Description);
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("\n[I] Change sniffing interface\n[C] Clear captured Ips\n[S] Show captured packages\n[E] Exit\n");
        Console.ForegroundColor = ConsoleColor.White;
    }
    private static void Device_OnPacketArrival(object sender, PacketCapture e)
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
    private static void ShowInterfaceMenu()
    {
        bool repeat;
        do
        {
            repeat = false;
            Console.Clear();
            var interfaces = CaptureDeviceList.Instance;
            Console.WriteLine("Available interfaces: ");
            for (int i = 0; i < interfaces.Count; i++)
            {
                Console.WriteLine($"[{i + 1}] {interfaces[i].Description}");
            }
            Console.WriteLine("\nSelect your interface using the number, press 0 to exit");
            var choice = Console.ReadKey().KeyChar.ToString();
            if (int.TryParse(choice, out int intChoice)) //Note: the + 1 and - 1 thing is only for UI user friendliness
            {
                Console.Clear();
                if (intChoice == 0)
                    return;
                device = interfaces[intChoice - 1];
            }
            else
                repeat = true;
        } while (repeat);


    }
}
