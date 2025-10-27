using System;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;
using System.Threading;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Linq;

namespace TabletModeWatcher
{
    class Program
    {
        // Config types
        class VidPidPair
        {
            public string Vid { get; set; } = "";
            public string Pid { get; set; } = "";
        }

        class Config
        {
            public List<VidPidPair> TargetVidPidPairs { get; set; } = new List<VidPidPair>();
            public string? LogPath { get; set; }
            public string MutexPrefix { get; set; } = "TabletModeWatcher";
            public int DebounceSeconds { get; set; } = 2;
            public string HkLmConvertibleSlateModePath { get; set; } = @"SYSTEM\\CurrentControlSet\\Control\\PriorityControl";
            public string HkCuImmersiveShellPath { get; set; } = @"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ImmersiveShell";
            public int BroadcastTimeoutMs { get; set; } = 2000;
            public long LogMaxBytes { get; set; } = 5 * 1024 * 1024; // 5 MB
        }

        static Config config = new Config();
        static string configFileName = "watcher.config.json";

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
            uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);

        const int HWND_BROADCAST = 0xffff;
        const uint WM_SETTINGCHANGE = 0x001A;
        const uint SMTO_ABORTIFHUNG = 0x0002;

        static DateTime lastScanUtc = DateTime.MinValue;
        static readonly object scanLock = new object();
        static TimeSpan debounce = TimeSpan.FromSeconds(2);

        static Mutex? instanceMutex = null;
        static bool ownsMutex = false;

        static ManagementEventWatcher? watcher = null;
        static ManualResetEventSlim shutdownEvent = new ManualResetEventSlim(false);

        static string logPath = "";

        static int Main(string[] args)
        {
            try
            {
                LoadConfig();

                debounce = TimeSpan.FromSeconds(Math.Max(0.5, config.DebounceSeconds));

                // determine log path (config or default)
                if (!string.IsNullOrWhiteSpace(config.LogPath))
                {
                    logPath = config.LogPath!;
                }
                else
                {
                    logPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "TabletModeWatcher", "watcher.log");
                }

                string? logDir = Path.GetDirectoryName(logPath)
                                 ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TabletModeWatcher");
                Directory.CreateDirectory(logDir);
                RotateLogIfNeeded();

                Log("Avvio TabletModeWatcher (headless) - filtro: PNPClass=Keyboard + VID/PID");

                string userSid = WindowsIdentity.GetCurrent().User?.Value ?? "nouser";
                string mutexName = $"Global\\{config.MutexPrefix}_{userSid}";

                bool createdNew = false;
                try
                {
                    instanceMutex = new Mutex(true, mutexName, out createdNew);
                    ownsMutex = createdNew;
                }
                catch (UnauthorizedAccessException)
                {
                    // fallback locale se non si può creare Global\
                    mutexName = $"{config.MutexPrefix}_{userSid}";
                    instanceMutex = new Mutex(true, mutexName, out createdNew);
                    ownsMutex = createdNew;
                }

                if (!ownsMutex)
                {
                    Log("Istanza già in esecuzione. Esco.");
                    return 0;
                }

                if (!IsAdministrator())
                {
                    Log("Il processo NON è in esecuzione come amministratore. Per scrivere in HKLM serve elevazione.");
                }

                CheckAndSetTabletMode();

                string queryString =
                    "SELECT * FROM __InstanceOperationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_PnPEntity'";

                watcher = new ManagementEventWatcher(new ManagementScope(@"\\.\root\cimv2"),
                                                    new WqlEventQuery(queryString));
                watcher.EventArrived += DeviceChangedEvent;
                watcher.Start();

                Log("Watcher avviato (in background).");

                // Setup graceful shutdown handlers
                Console.CancelKeyPress += (s, e) =>
                {
                    Log("Console.CancelKeyPress ricevuto; avvio shutdown.");
                    e.Cancel = true;
                    shutdownEvent.Set();
                };
                AppDomain.CurrentDomain.ProcessExit += (s, e) =>
                {
                    Log("ProcessExit ricevuto; avvio shutdown.");
                    shutdownEvent.Set();
                };

                // Wait until shutdown requested
                shutdownEvent.Wait();

                // Stop watcher gracefully
                try
                {
                    if (watcher != null)
                    {
                        watcher.Stop();
                        watcher.EventArrived -= DeviceChangedEvent;
                        watcher.Dispose();
                        watcher = null;
                    }
                }
                catch (Exception ex)
                {
                    Log("Errore durante lo stop del watcher: " + ex.ToString());
                }
            }
            catch (ThreadInterruptedException)
            {
            }
            catch (Exception ex)
            {
                Log("Eccezione Main: " + ex.ToString());
            }
            finally
            {
                try
                {
                    if (instanceMutex is not null)
                    {
                        try
                        {
                            if (ownsMutex)
                            {
                                try { instanceMutex.ReleaseMutex(); } catch { }
                            }
                        }
                        catch { }
                        instanceMutex.Dispose();
                        instanceMutex = null;
                    }
                }
                catch { }
            }

            Log("Termino.");
            return 0;
        }

        static void DeviceChangedEvent(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var eventType = e.NewEvent.ClassPath.ClassName;
                var entity = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                string deviceId = entity["DeviceID"]?.ToString() ?? "";
                string pnpClass = entity["PNPClass"]?.ToString() ?? "";

                Log($"Evento WMI ricevuto: {eventType} PNPClass={pnpClass} DeviceID={deviceId}");

                bool doScan = false;
                lock (scanLock)
                {
                    var now = DateTime.UtcNow;
                    if (now - lastScanUtc > debounce)
                    {
                        lastScanUtc = now;
                        doScan = true;
                    }
                }

                if (doScan)
                {
                    Log("Eseguo rescan dispositivi in seguito a evento PnP...");
                    CheckAndSetTabletMode();
                }
                else
                {
                    Log("Evento ignorato per debounce.");
                }
            }
            catch (Exception ex)
            {
                Log("Eccezione DeviceChangedEvent: " + ex.ToString());
            }
        }

        // Ora matching semplice: PNPClass == "Keyboard" E VID/PID corrispondenti a config
        static bool MatchesVidPidAndPnpClass(ManagementObject device)
        {
            try
            {
                string pnpClass = device["PNPClass"]?.ToString() ?? "";
                if (!string.Equals(pnpClass, "Keyboard", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Prendi gli HardwareID se presenti
                var hwIds = device["HardwareID"] as string[]; // spesso contiene VID_/PID_ entries
                string deviceId = device["DeviceID"]?.ToString() ?? "";

                // Precompila pattern per ogni coppia VID/PID dalla config
                foreach (var pair in config.TargetVidPidPairs)
                {
                    if (string.IsNullOrWhiteSpace(pair.Vid) || string.IsNullOrWhiteSpace(pair.Pid))
                        continue;

                    // accetta formati esadecimali con/ senza zeri, ma useremo esatta escape
                    string pattern = $"VID_{Regex.Escape(pair.Vid)}.*PID_{Regex.Escape(pair.Pid)}";
                    var re = new Regex(pattern, RegexOptions.IgnoreCase);

                    if (hwIds != null && hwIds.Any(h => re.IsMatch(h)))
                        return true;

                    if (!string.IsNullOrEmpty(deviceId) && re.IsMatch(deviceId))
                        return true;

                    // fallback semplice: verifica presenza di substrings (più permissivo)
                    if (!string.IsNullOrEmpty(deviceId)
                        && deviceId.IndexOf($"VID_{pair.Vid}", StringComparison.OrdinalIgnoreCase) >= 0
                        && deviceId.IndexOf($"PID_{pair.Pid}", StringComparison.OrdinalIgnoreCase) >= 0)
                        return true;
                }
            }
            catch (Exception ex)
            {
                Log("Errore MatchesVidPidAndPnpClass: " + ex.ToString());
            }

            return false;
        }

        static void CheckAndSetTabletMode()
        {
            try
            {
                Log("Eseguo controllo dispositivi PnP (rescan)...");
                bool keyboardPresent = false;
                int scanned = 0;
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity"))
                {
                    foreach (ManagementObject device in searcher.Get())
                    {
                        scanned++;
                        string id = device["DeviceID"]?.ToString() ?? "";

                        // Se il dispositivo è classe Keyboard e ha VID/PID che corrispondono, lo consideriamo target
                        if (MatchesVidPidAndPnpClass(device))
                        {
                            keyboardPresent = true;
                            Log($"Dispositivo target (Keyboard VID/PID) trovato durante rescan: {id}");
                            break;
                        }

                        if (scanned <= 5)
                        {
                            // log diagnostico delle prime 5 entry per capire gli ID reali
                            Log($"Scansionato DeviceID[{scanned}]: {id} PNPClass={(device["PNPClass"]?.ToString() ?? "")}");
                            var hw = device["HardwareID"] as string[];
                            if (hw != null && hw.Length > 0)
                            {
                                Log($"  HardwareID[0]: {hw[0]}");
                            }
                        }
                    }
                }
                Log($"Rescan completato. Dispositivi scansionati: {scanned}. keyboardPresent={keyboardPresent}");
                SetTabletMode(!keyboardPresent);
            }
            catch (Exception ex)
            {
                Log("Eccezione CheckAndSetTabletMode: " + ex.ToString());
            }
        }

        static void SetTabletMode(bool tabletMode)
        {
            try
            {
                Log($"SetTabletMode chiamato. tabletMode={tabletMode}");

                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(config.HkLmConvertibleSlateModePath, true))
                    {
                        if (key != null)
                        {
                            int value = tabletMode ? 0 : 1;
                            key.SetValue("ConvertibleSlateMode", value, RegistryValueKind.DWord);
                            Log($"Impostato HKLM ConvertibleSlateMode = {value}");
                        }
                        else
                        {
                            Log($"Impossibile aprire HKLM\\...\\PriorityControl (chiave nulla): {config.HkLmConvertibleSlateModePath}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log("Errore scrittura HKLM ConvertibleSlateMode: " + ex.ToString());
                }

                try
                {
                    using (var key = Registry.CurrentUser.CreateSubKey(config.HkCuImmersiveShellPath))
                    {
                        if (key != null)
                        {
                            int val = tabletMode ? 1 : 0;
                            key.SetValue("TabletMode", val, RegistryValueKind.DWord);
                            Log($"Impostato HKCU ImmersiveShell\\TabletMode = {val}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log("Errore scrittura HKCU ImmersiveShell TabletMode: " + ex.ToString());
                }

                try
                {
                    UIntPtr result;
                    SendMessageTimeout(new IntPtr(HWND_BROADCAST), WM_SETTINGCHANGE, UIntPtr.Zero,
                        "ConvertibleSlateMode", SMTO_ABORTIFHUNG, (uint)config.BroadcastTimeoutMs, out result);
                    SendMessageTimeout(new IntPtr(HWND_BROADCAST), WM_SETTINGCHANGE, UIntPtr.Zero,
                        "ImmersiveShell", SMTO_ABORTIFHUNG, (uint)config.BroadcastTimeoutMs, out result);
                    Log("WM_SETTINGCHANGE inviato in broadcast.");
                }
                catch (Exception ex)
                {
                    Log("Errore Broadcast WM_SETTINGCHANGE: " + ex.ToString());
                }
            }
            catch (Exception ex)
            {
                Log("Eccezione SetTabletMode: " + ex.ToString());
            }
        }

        static bool IsAdministrator()
        {
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                return false;
            }
        }

        static void LoadConfig()
        {
            try
            {
                string cfgPath = Path.Combine(AppContext.BaseDirectory, configFileName);

                if (!File.Exists(cfgPath))
                {
                    // write default example config to disk
                    var example = new Config
                    {
                        TargetVidPidPairs = new List<VidPidPair> {
                            new VidPidPair { Vid = "0B05", Pid = "1B6E" }
                        },
                        LogPath = "",
                        MutexPrefix = "TabletModeWatcher",
                        DebounceSeconds = 2,
                        HkLmConvertibleSlateModePath = @"SYSTEM\\CurrentControlSet\\Control\\PriorityControl",
                        HkCuImmersiveShellPath = @"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ImmersiveShell",
                        BroadcastTimeoutMs = 2000,
                        LogMaxBytes = 5 * 1024 * 1024
                    };
                    var options = new JsonSerializerOptions { WriteIndented = true };
                    File.WriteAllText(cfgPath, JsonSerializer.Serialize(example, options));
                    Console.WriteLine($"File di configurazione creato: {cfgPath}. Modifica i valori sensibili prima di eseguire.");
                }

                string json = File.ReadAllText(cfgPath);
                var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var loaded = JsonSerializer.Deserialize<Config>(json, opts);
                if (loaded != null)
                {
                    config = loaded;
                }

                // ensure defaults if missing
                if (config.TargetVidPidPairs == null || config.TargetVidPidPairs.Count == 0)
                {
                    config.TargetVidPidPairs = new List<VidPidPair> {
                        new VidPidPair { Vid = "0B05", Pid = "1B6E" }
                    };
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Errore caricamento config: " + ex.ToString());
                // Se non si riesce a leggere la config, continuare con valori embedded
            }
        }

        static void RotateLogIfNeeded()
        {
            try
            {
                if (string.IsNullOrWhiteSpace(logPath)) return;
                if (File.Exists(logPath))
                {
                    var fi = new FileInfo(logPath);
                    if (fi.Length >= config.LogMaxBytes && config.LogMaxBytes > 0)
                    {
                        string archive = logPath + ".1";
                        try
                        {
                            if (File.Exists(archive)) File.Delete(archive);
                            File.Move(logPath, archive);
                        }
                        catch { /* non fatale */ }
                    }
                }
            }
            catch { }
        }

        static void Log(string message)
        {
            try
            {
                RotateLogIfNeeded();
                string line = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC] {message}";
                File.AppendAllText(logPath, line + Environment.NewLine);
            }
            catch
            {
                // Non rompere il servizio per problemi di log
            }
        }
    }
}