using NetworkApp.NetworkServices;
using SharpPcap;
using System.Text.RegularExpressions;
public class Program
{
    private static ICaptureDevice device = null;
    private static bool IsSniffing = false;

    public static void Main(string[] args)
    {
        Console.Title = "Xwing Sniffer";
        bool run = true;
        ShowSniffer();
        while (run)
        {


            if (IsSniffing)
            {
                device.OnPacketArrival += PackageService.Device_OnPacketArrival;
                device.Open(SharpPcap.DeviceModes.Promiscuous);
                device.StartCapture();
            }
            var currentKey = Console.ReadKey();
            if (currentKey.KeyChar is 'e' || currentKey.KeyChar is 'E')
            {

                run = false;
            }
            else if (currentKey.KeyChar is 'i' || currentKey.KeyChar is 'I')
            {
                if (!IsSniffing)
                    continue;
                device.StopCapture();
                ShowInterfaceMenu();
                ShowSniffer();
            }
            else if (currentKey.KeyChar is 'c' || currentKey.KeyChar is 'C')
            {
                if (!IsSniffing)
                    continue;
                PackageService.ClearIps();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\nIps cleared!");
                Console.ForegroundColor = ConsoleColor.White;
            }
            else if (currentKey.KeyChar is 'm' || currentKey.KeyChar is 'M')
            {
                if (IsSniffing)
                    device.StopCapture();
                DisplayChangeMac();
                Console.Clear();
                ShowSniffer();
            }
            else if (currentKey.KeyChar is 's' || currentKey.KeyChar is 'S')
            {
                if (!IsSniffing)
                    continue;
                device.StopCapture();
                DisplayCapturedPackages();
                ShowSniffer();
            }
            else if (currentKey.KeyChar is 't' || currentKey.KeyChar is 'T')
            {
                IsSniffing = IsSniffing ? false : true;
                try
                {
                    if (IsSniffing)
                        device = CaptureDeviceList.Instance.FirstOrDefault();
                    Console.Clear();
                    ShowSniffer();
                }
                catch (DllNotFoundException)
                {
                    IsSniffing = false;
                    Console.Clear();
                    Console.WriteLine("Npcap not found! Make sure you have Npcap installed. Check the installation guide for more details.");
                    Thread.Sleep(5000);
                    Console.Clear();
                    ShowSniffer();
                }

            }
        }
        if (IsSniffing)
        {
            device.StopCapture();
            device.Close();
        }
    }
    private static void DisplayChangeMac()
    {
        bool repeat;
        do
        {
            repeat = false;
            Console.Clear();
            string newMac;
            var macs = MacService.GetMacs();
            if (macs is null)
            {
                Thread.Sleep(5000);
                return;
            }
            for (int i = 0; i < macs.Count; i++)
            {
                Console.WriteLine($"[{i + 1}] {macs[i].adapterName} ({macs[i].adapterValue})");
            }
            Console.WriteLine("\nSelect your adapter to spoof using the number, press 0 to exit");
            var choice = Console.ReadKey().KeyChar.ToString();
            if (int.TryParse(choice, out int intChoice)) //Note: the + 1 and - 1 thing is only for UI user friendliness
            {
                Console.Clear();
                if (intChoice == 0)
                    return;
                if (intChoice > macs.Count)
                {
                    Thread.Sleep(5000);
                    Console.WriteLine("Invalid number!");
                    return;
                }
                Console.WriteLine("Enter a new MAC address: (Format: FF-FF-FF-FF-FF-FF) or leave blank to get a random MAC address (100% valid if the validMacPrefixes file exists).\nNote: This action may take a few seconds. If the adapter doesn't enable automatically, enable it manually.\n\nEnter 'e' to exit:");
                string? input = Console.ReadLine();
                if (string.IsNullOrEmpty(input))
                    newMac = MacService.GenerateRandomMac();
                else if (input == "e" || input == "E")
                    return;
                else
                    if (Regex.Match(input, @"^([0-9A-Fa-f]{2}[-]){5}([0-9A-Fa-f]{2})$").Success)
                    newMac = input;
                else
                {
                    Console.Clear();
                    Console.WriteLine("Given Mac adress was not in the right format!");
                    Thread.Sleep(4000);
                    return;
                }


                if (!MacService.SpoofMAC(newMac, macs[intChoice - 1].adapterName))
                    return;
                Console.Clear();
                Console.WriteLine("Mac adress got sucessfully spoofed!");
                Thread.Sleep(3000);

            }
            else
                repeat = true;

        } while (repeat);

    }
    private static void DisplayCapturedPackages()
    {
        bool repeat;
        string txtContent = string.Empty;
        do
        {
            repeat = true;
            Console.Clear();
            foreach (var package in PackageService.GetIps())
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
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("____  ___       .__                            \r\n\\   \\/  /_  _  _|__| ____    ____              \r\n \\     /\\ \\/ \\/ /  |/    \\  / ___\\             \r\n /     \\ \\     /|  |   |  \\/ /_/  >            \r\n/___/\\  \\ \\/\\_/ |__|___|  /\\___  /             \r\n      \\_/               \\//_____/              \r\n  _________      .__  _____  _____             \r\n /   _____/ ____ |__|/ ____\\/ ____\\___________ \r\n \\_____  \\ /    \\|  \\   __\\\\   __\\/ __ \\_  __ \\\r\n /        \\   |  \\  ||  |   |  | \\  ___/|  | \\/\r\n/_______  /___|  /__||__|   |__|  \\___  >__|   \r\n        \\/     \\/                     \\/       "); //Xwing Sniffer
        Console.ForegroundColor = ConsoleColor.White;
        if (IsSniffing)
            Console.WriteLine("Currently sniffing on: " + device.Description);
        else
            Console.WriteLine("Press T to start sniffing");
        Console.ForegroundColor = ConsoleColor.Magenta;
        if (IsSniffing)
            Console.WriteLine("\n[I] Change sniffing interface\n[C] Clear captured Ips\n[S] Show captured packages\n[M] Change Systems Mac\n[E] Exit\n");
        else
            Console.WriteLine("\n[M] Change Systems Mac\n[E] Exit\n");

        Console.ForegroundColor = ConsoleColor.White;
    }


    private static void ShowInterfaceMenu()
    {
        bool repeat;
        do
        {
            repeat = false;
            Console.Clear();
            var interfaces = CaptureDeviceList.Instance;
            if (interfaces is null)
            {
                Console.WriteLine("No interfaces found!");
                return;
            }
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
