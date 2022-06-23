from random import choice, randint

from os.path import dirname
from json import loads


def random_user_agent() -> str:
    """
    * Generate random user agent for headers.

    ? Returns the randomly generated user agent or
    """

    def fetch_data() -> list[str]:
        base_dir: str = dirname(__file__)

        user_agents: list[str] = []

        try:
            with open(
                    f"{base_dir}/user_agents/user_agents.json",
                    "r",
                    encoding="utf-8"
                ) as data:
                for user_agent_ in data:
                    user_agent_: dict[str, str] = loads(user_agent_)

                    user_agents.append(user_agent_)
        except FileNotFoundError:
            raise SystemExit
        else:
            floor_: int = randint(1, 1100)
            top_: int = randint(floor_, floor_*2)

            return user_agents[floor_:top_]

    yield choice(fetch_data())["user_agent"]
