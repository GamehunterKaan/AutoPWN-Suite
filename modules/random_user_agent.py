from random import choice, randint

from os.path import dirname
from json import loads

from logger import Logger


def random_user_agent() -> str:
    """
    * Generate random user agent for headers.

    ? Returns the randomly generated user agent or
    """
    log = Logger()
    def fetch_data() -> list[str]:
        base_dir: str = dirname(__file__)

        user_agents: list[str] = []

        try:
            file = choice(
                    [
                        "user_agents_1.json",
                        "user_agents_2.json",
                        "user_agents_3.json",
                        "user_agents_4.json"
                    ]
                )
            with open(
                    f"{base_dir}/user_agents/{file}",
                    "r",
                    encoding="utf-8"
                ) as data:
                for user_agent_ in data:
                    user_agent_: dict[str, str] = loads(user_agent_)

                    user_agents.append(user_agent_)
        except FileNotFoundError:
            log.logger("error", "User agent database not found.")
            raise SystemExit
        else:
            floor_: int = randint(1, 2500)
            top_: int = randint(floor_, floor_*2)

            return user_agents[floor_:top_]

    yield choice(fetch_data())["user_agent"]
