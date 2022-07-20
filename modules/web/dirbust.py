from os.path import dirname

from modules.random_user_agent import random_user_agent
from requests import get


def dirbust(target_url, console, log) -> None:
    if not target_url.endswith("/"):
        target_url += "/"

    curdir = dirname(__file__)
    dirs_db = f"{curdir}/../data/web_discovery.txt"

    try:
        with open(dirs_db, "r") as f:
            dirs = f.read().splitlines()
    except FileNotFoundError:
        log.logger("error", "Web discovery database not found.")

    found_dirs = [target_url]

    for dir in dirs:
        test_url = f"{target_url}{dir}"
        if test_url in found_dirs:
            continue

        headers = {"User-Agent": next(random_user_agent(log))}

        try:
            req = get(test_url, headers=headers)
        except Exception as e:
            log.logger("error", e)
        else:
            if req.status_code == 404:
                continue

            found_dirs.append(test_url)

            if req.is_redirect:
                console.print(
                    f"[red][[/red][green]+[/green][red]][/red]"
                    + f" [white]DIR :[/white] {test_url} -> {req.url}"
                )
            else:
                console.print(
                    f"[red][[/red][green]+[/green][red]][/red]"
                    + f" [white]DIR :[/white] {test_url}"
                )
