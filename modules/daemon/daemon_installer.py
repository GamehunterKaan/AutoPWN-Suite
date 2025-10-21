from modules.banners import print_banner
from configparser import ConfigParser
import re, os

def _get_menu_choice(console, prompt: str, options: dict, default: str = None) -> str:
    """
    Displays a menu of options, gets user input, and validates it.

    Args:
        console: The Rich console object.
        prompt: The question to ask the user.
        options: A dictionary where keys are choices (e.g., '1') and
                 values are descriptions (e.g., 'Email').
        default: The default choice key to return if the user enters nothing.

    Returns:
        The key of the chosen option.
    """
    while True:
        console.print(prompt)
        for key, value in options.items():
            console.print(f"  [cyan]{key}[/cyan]. {value}")
        choice = console.input(f"Enter your choice ({'-'.join(options.keys())}): ").strip()
        if default and choice == "":
            return default
        if choice in options:
            return choice
        console.print(f"[red]Invalid choice. Please enter one of {list(options.keys())}.[/red]")

def _get_validated_int(console, prompt: str, default: int = None) -> int:
    """Gets and validates an integer input from the user."""
    while True:
        user_input = console.input(prompt)
        if user_input == "" and default is not None:
            return default
        try:
            return int(user_input)
        except ValueError:
            console.print("[red]Invalid input. Please enter a whole number.[/red]")

def _get_validated_email(console, prompt: str, allow_empty: bool = False) -> str:
    """Gets and validates an email address from the user."""
    # A simple regex for email validation
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    while True:
        email = console.input(prompt)
        if allow_empty and email == "":
            return ""
        if email and re.match(email_regex, email):
            return email
        console.print("[red]Invalid email format. Please enter a valid email address.[/red]")

def _get_non_empty_input(console, prompt: str) -> str:
    """Gets a non-empty string input from the user."""
    while True:
        user_input = console.input(prompt).strip()
        if user_input:
            return user_input
        console.print("[red]This field cannot be empty.[/red]")

def CreateConfig(console, config_filename=""):
    console.print("Welcome to AutoPWN Suite Config Creator!")

    scan_interval = _get_validated_int(console, "Enter the scan interval in [cyan]seconds[/cyan]: ")

    report_choice = _get_menu_choice(
        console,
        "Would you like to enable email or webhook notifications?",
        {"1": "Email", "2": "Webhook", "3": "None"}
    )

    if report_choice == "1":
        report_method = 'email'
        report_email = _get_validated_email(console, "Enter your [cyan]email address[/cyan]: ")
        report_email_password = _get_non_empty_input(console, "Enter your [cyan]email password[/cyan]: ")
        report_email_to = _get_validated_email(console, "Enter the email address to [cyan]send the report to[/cyan]: ")
        report_email_from = _get_validated_email(console, "Enter the email address to [cyan]send from[/cyan] (leave empty to use login email): ", allow_empty=True)
        report_email_server = _get_non_empty_input(console, "Enter the [cyan]email server[/cyan] to send the report from: ")
        report_email_server_port = _get_validated_int(console, "Enter the [cyan]email port[/cyan] to send the report from: ")
        console.print("[green]Email notifications enabled.[/green]")
    elif report_choice == "2":
        report_method = 'webhook'
        report_webhook = console.input("Enter your [cyan]webhook URL[/cyan]: ")
        console.print("[green]Webhook notifications enabled.[/green]")
    else: # choice == "3"
        report_method = 'none'
        console.print("[yellow]No notifications enabled.[/yellow]")

    target = console.input("Enter your [cyan]target[/cyan] (Leave empty for auto detection): ")
    host_file = console.input("Enter [cyan]host file[/cyan] (Leave empty for none - will override target): ")

    if target == "" and host_file == "":
        skip_discovery = False
    else:
        skip_discovery_input = console.input("Would you like to [cyan]skip discovery[/cyan]? (y/n) ")
        skip_discovery = skip_discovery_input.lower() == "y"

    api_key = console.input("Enter [cyan]API key[/cyan] (Leave empty for none): ")
    nmap_flags = console.input("Enter [cyan]nmap flags[/cyan] (Leave empty for none): ")
    speed = _get_validated_int(console, "Enter [cyan]speed[/cyan] (0-5, Leave empty for default): ", default=3)


    scan_type_choice = _get_menu_choice(
        console,
        "Pick [cyan]scan type[/cyan] for host discovery (Leave empty for ARP): ",
        {"1": "ARP", "2": "Ping"},
        default="1"
    )
    scan_type = "arp" if scan_type_choice == "1" else "ping"

    host_timeout = _get_validated_int(console, "Enter [cyan]host timeout[/cyan] (Leave empty for default): ", default=240)

    scan_method_choice = _get_menu_choice(
        console,
        "Enter [cyan]Scan Method[/cyan] (Leave empty for Normal): ",
        {"1": "Normal", "2": "Evade"},
        default="1"
    )
    scan_method = "normal" if scan_method_choice == "1" else "evade"

    output_folder = console.input("Enter [cyan]output folder[/cyan] (Leave empty for default): ")
    if output_folder == "":
        output_folder = "outputs"
    output_type = console.input("Enter [cyan]output type[/cyan] (Leave empty for html): ")
    if output_type == "":
        output_type = "html"

    console.print("Creating config file...")
    config = ConfigParser()
    config['AUTOPWN'] = {
        'scan_interval': str(scan_interval),
        'target': target,
        'hostfile': host_file,
        'apikey': api_key,
        'scan_type': scan_type,
        'nmapflags': nmap_flags,
        'speed': speed,
        'auto': True,
        'mode': scan_method,
        'skip_discovery': str(skip_discovery),
        'output_folder': output_folder,
        'output_type': output_type,
        'host_timeout': host_timeout,
    }
    if report_method == 'email':
        config['REPORT'] = {'method': report_method}
        config['REPORT']['email'] = report_email
        config['REPORT']['email_password'] = report_email_password
        config['REPORT']['email_to'] = report_email_to
        config['REPORT']['email_from'] = report_email_from
        config['REPORT']['email_server'] = report_email_server
        config['REPORT']['email_port'] = str(report_email_server_port)
    elif report_method == 'webhook':
        config['REPORT'] = {'method': report_method}
        config['REPORT']['webhook'] = report_webhook


    if not config_filename:
        config_file = console.input("Enter [cyan]config file name[/cyan] (Leave empty for autopwn.conf): ")
        if config_file == "":
            config_file = "autopwn.conf"
    else:
        config_file = config_filename
    try:
        open(config_file, 'r', encoding='utf-8').close()
        overwrite_config = console.input(f"[yellow]Config file '{config_file}' already exists. Would you like to overwrite it?[/yellow] (y/n): ")
        if overwrite_config.lower() != 'y':
            console.print(f"[red]Config file '{config_file}' not overwritten.[/red]")
            return
        else:
            os.remove(config_file)
            with open(config_file, 'w', encoding='utf-8') as configfile:
                config.write(configfile)   
        
    except FileNotFoundError:
        with open(config_file, 'w', encoding='utf-8') as configfile:
            config.write(configfile)
        

    console.print(f"[green]Config file '{config_file}' created successfully![/green]")

def InstallDaemon(console):
    print_banner(console)
    CreateConfig(console, "autopwn-daemon.conf")

def UninstallDaemon(console):
    print_banner(console)
