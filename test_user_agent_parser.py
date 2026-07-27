import unittest

from user_agent_parser import identify_bot, process_bot_stats


OBSERVED_BOT_USER_AGENTS = {
    "360Spider": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 "
        "Safari/537.36 Edg/140.0.0.0; 360Spider"
    ),
    "OAI-SearchBot": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 "
        "Safari/537.36; compatible; OAI-SearchBot/1.4; robots.txt; "
        "+https://openai.com/searchbot"
    ),
    "NVIDIA Bot": (
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:72.0) "
        "Gecko/20100101 Firefox/72.0 (compatible; "
        "[nvidia]-[psirt@nvidia.com]-[nspect-i05s-fieu]-[nvidiabot]; "
        "+https://github.com/rom1504/img2dataset)"
    ),
}


class UserAgentParserTests(unittest.TestCase):
    def test_identifies_observed_bot_user_agents(self):
        for expected_name, user_agent in OBSERVED_BOT_USER_AGENTS.items():
            with self.subTest(expected_name=expected_name):
                self.assertEqual(identify_bot(user_agent), expected_name)

    def test_bot_stats_include_metadata_for_observed_bots(self):
        events = [
            {"userAgent": user_agent}
            for user_agent in OBSERVED_BOT_USER_AGENTS.values()
        ]

        stats = process_bot_stats(events)

        self.assertEqual(
            {item["name"] for item in stats}, set(OBSERVED_BOT_USER_AGENTS)
        )
        self.assertTrue(all(item["operator"] != "Unknown" for item in stats))


if __name__ == "__main__":
    unittest.main()
