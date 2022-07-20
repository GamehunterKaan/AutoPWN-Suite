from json import loads
from os.path import dirname
from random import choice, randint


def random_user_agent(log) -> str:
    """
    * Generate random user agent for headers.

    ? Returns the randomly generated user agent
    """

    def fetch_data() -> list[str]:
        base_dir: str = dirname(__file__)

        user_agents: list[str] = []

        try:
            with open(
                f"{base_dir}/data/user_agents.json", "r", encoding="utf-8"
            ) as data:
                for user_agent_ in data:
                    user_agent_: dict[str, str] = loads(user_agent_)

                    user_agents.append(user_agent_)
        except FileNotFoundError:
            log.logger("error", "User agent database not found.")
            raise SystemExit
        else:
            floor_: int = randint(1, 450)
            top_: int = randint(floor_ + 1, floor_ * 2)

            return user_agents[floor_:top_]

    yield choice(fetch_data())["user_agent"]
