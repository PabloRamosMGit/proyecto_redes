## Required Configuration

This project requires access to the Lab Network via VPN. The recommended environment is Ubuntu or WSL (Windows Subsystem for Linux).

1. **Install OpenConnect:**
   ```bash
   sudo apt install openconnect
   ```
2. **Connect to the Lab Network:**
   ```bash
   sudo openconnect --protocol=anyconnect <Lab Network Address> --user=<username>
   ```
   Replace `<Lab Network Address>` with the address provided by your lab administrator and `<username>` with your own username.

---

## How to Use This Project

1. Clone or download the repository to your local machine.
2. Ensure you are connected to the Lab Network VPN as described above.
3. Install Python 3 if not already available.
4. Run the CLI tool:
   ```bash
   python3 restconf_cli.py --help
   ```
   This will show all available commands and options.

### Example Usage
- To view interface status:
  ```bash
  python3 restconf_cli.py get-interfaces
  ```
- To create a Loopback interface:
  ```bash
  python3 restconf_cli.py post-loopback --name Loopback123 --ip 10.123.123.123 --desc "Test Loopback"
  ```
- To delete a Loopback interface:
  ```bash
  python3 restconf_cli.py delete-loopback --name Loopback123
  ```

For more details, use the `--help` option with any command.

---

Feel free to customize the commands and options as needed for your lab environment.