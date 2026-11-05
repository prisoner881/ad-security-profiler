"""collector_daemon.next_occurrence / previous_occurrence, across both
daylight-saving changes, and platform_client.parse_schedule."""
import unittest
from datetime import datetime, timedelta, timezone

import collector_daemon as cd
import platform_client as pc


def utc(*args):
    return datetime(*args, tzinfo=timezone.utc)


class Occurrences(unittest.TestCase):
    chicago = pc.Schedule("02:30", "America/Chicago")

    def test_plain_day(self):
        # 02:30 CST = 08:30Z in January.
        self.assertEqual(cd.next_occurrence(self.chicago, utc(2026, 1, 10, 0, 0)),
                         utc(2026, 1, 10, 8, 30))
        self.assertEqual(cd.next_occurrence(self.chicago, utc(2026, 1, 10, 8, 30)),
                         utc(2026, 1, 11, 8, 30))
        self.assertEqual(cd.previous_occurrence(self.chicago, utc(2026, 1, 10, 8, 30)),
                         utc(2026, 1, 10, 8, 30))
        self.assertEqual(cd.previous_occurrence(self.chicago, utc(2026, 1, 10, 8, 29)),
                         utc(2026, 1, 9, 8, 30))

    def test_summer_time(self):
        # 02:30 CDT = 07:30Z in July.
        self.assertEqual(cd.next_occurrence(self.chicago, utc(2026, 7, 1, 0, 0)),
                         utc(2026, 7, 1, 7, 30))

    def test_spring_forward(self):
        # 2026-03-08: 02:00 CST jumps to 03:00 CDT; 02:30 does not exist that
        # day. The run still happens once that day, and the next one is the
        # following day's 02:30 CDT.
        first = cd.next_occurrence(self.chicago, utc(2026, 3, 8, 0, 0))
        self.assertEqual(first.date(), datetime(2026, 3, 8).date())
        self.assertEqual(cd.next_occurrence(self.chicago, first), utc(2026, 3, 9, 7, 30))

    def test_fall_back(self):
        # 2026-11-01: 02:00 CDT falls back to 01:00 CST; 02:30 occurs once.
        first = cd.next_occurrence(self.chicago, utc(2026, 11, 1, 0, 0))
        self.assertEqual(first, utc(2026, 11, 1, 8, 30))
        self.assertEqual(cd.next_occurrence(self.chicago, first), utc(2026, 11, 2, 8, 30))

    def test_runs_once_a_day_for_a_year(self):
        for zone in ("America/Chicago", "Europe/London", "Australia/Sydney", "UTC"):
            schedule = pc.Schedule("02:30", zone)
            moment = utc(2026, 1, 1)
            days = set()
            for _ in range(365):
                moment = cd.next_occurrence(schedule, moment)
                local_day = moment.astimezone(schedule.zone).date()
                self.assertNotIn(local_day, days, f"{zone}: two runs on {local_day}")
                days.add(local_day)
                self.assertLess(cd.previous_occurrence(schedule, moment + timedelta(hours=1)),
                                moment + timedelta(seconds=1))
            self.assertEqual(len(days), 365, zone)


class ParseSchedule(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(str(pc.parse_schedule(None)), "02:00 UTC")

    def test_normalised(self):
        self.assertEqual(pc.parse_schedule({"time": "2:05", "timezone": "Europe/Paris"}).time,
                         "02:05")

    def test_refused(self):
        for data in ({"time": "24:00"}, {"time": "2:5"}, {"time": "noon"},
                     {"timezone": "Mars/Olympus"}):
            with self.subTest(data=data), self.assertRaises(pc.ConfigError):
                pc.parse_schedule(data)


if __name__ == "__main__":
    unittest.main()
