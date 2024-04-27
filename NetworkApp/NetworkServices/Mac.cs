using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace NetworkApp.NetworkServices
{
    public static class MacService
    {
        public static List<(string adapterName, string adapterValue)>? GetMacs()
        {
            List<(string adapterName, string adapterValue)> macInformation = new List<(string adapterName, string adapterValue)>();
            try
            {
                using RegistryKey NetworkAdapters = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}");
                foreach (string adapter in NetworkAdapters.GetSubKeyNames())
                {
                    if (adapter != "Properties")
                    {
                        using RegistryKey NetworkAdapter = Registry.LocalMachine.OpenSubKey($"SYSTEM\\CurrentControlSet\\Control\\Class\\{{4d36e972-e325-11ce-bfc1-08002be10318}}\\{adapter}", true);
                        if (NetworkAdapter.GetValue("BusType") != null)
                        {
                            macInformation.Add((NetworkAdapter.GetValue("DriverDesc")?.ToString(), NetworkAdapter.GetValue("NetworkAddress")?.ToString()));
                        }
                    }
                }
                return macInformation;

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading MAC address: {ex.Message}\nCheck if the Program runs in admin mode!");
                return null;
            }
        }
        public static bool SpoofMAC(string mac, string adaptername)

        {
            bool success = true;

            using RegistryKey NetworkAdapters = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}");
            foreach (string adapter in NetworkAdapters.GetSubKeyNames())
            {
                if (adapter != "Properties")
                {
                    try
                    {
                        using RegistryKey NetworkAdapter = Registry.LocalMachine.OpenSubKey($"SYSTEM\\CurrentControlSet\\Control\\Class\\{{4d36e972-e325-11ce-bfc1-08002be10318}}\\{adapter}", true);
                        if (NetworkAdapter.GetValue("DriverDesc")?.ToString() == adaptername)
                        {
                            NetworkAdapter.SetValue("NetworkAddress", mac);
                            string adapterId = NetworkAdapter.GetValue("NetCfgInstanceId").ToString()!;
                            Enable_LocalAreaConnection(adapterId, false);

                        }
                    }
                    catch (System.Security.SecurityException ex)
                    {
                        Console.WriteLine("\n[X] Start the program in admin mode to spoof your MAC address!");
                        success = false;
                        break;
                    }
                }
            }

            return success;
        }
        private static void Enable_LocalAreaConnection(string adapterId, bool enable = true, string adapterInterFaceName = "")
        {
            string interfaceName = "Ethernet";
            if (string.IsNullOrEmpty(adapterInterFaceName))
            {
                foreach (NetworkInterface i in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (i.Id == adapterId)
                    {
                        interfaceName = i.Name;
                        break;
                    }
                }
            }
            else
                interfaceName = adapterInterFaceName;


            string control;
            if (enable)
                control = "enable";
            else
                control = "disable";

            System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo("netsh", $"interface set interface \"{interfaceName}\" {control}");
            System.Diagnostics.Process p = new System.Diagnostics.Process();
            p.StartInfo = psi;
            p.Start();
            p.WaitForExit();

            if (!enable)
            {
                Thread.Sleep(2000);

                Enable_LocalAreaConnection(adapterId, true, interfaceName);
            }
        }
        public static string GenerateRandomMac()
        {
            string chars = "ABCDEF0123456789";
            string windows = "26AE";
            string result = "";
            Random random = new Random();

            result += chars[random.Next(chars.Length)];
            result += windows[random.Next(windows.Length)];

            for (int i = 0; i < 5; i++)
            {
                result += "-";
                result += chars[random.Next(chars.Length)];
                result += chars[random.Next(chars.Length)];

            }

            return result;
        }



    }
}
