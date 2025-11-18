import pytest

from bountybot.scanner.nuclei_runner import (
    DEFAULT_PROFILE,
    available_profiles,
    build_nuclei_command,
)


def test_default_profile_is_registered():
    profiles = available_profiles()
    assert DEFAULT_PROFILE in profiles


def test_build_command_includes_base_arguments():
    target = "https://example.com"
    cmd = build_nuclei_command(target)

    assert cmd[:7] == [
        "nuclei",
        "-u",
        target,
        "-silent",
        "-jsonl",
        "-no-meta",
        "-stats",
    ]
    assert "-severity" in cmd  # fast profile adds severity filters


def test_build_command_thorough_profile_has_no_filters():
    cmd = build_nuclei_command("https://example.com", profile="thorough")
    assert "-severity" not in cmd
    assert "-tags" not in cmd


def test_build_command_errors_on_unknown_profile():
    with pytest.raises(ValueError):
        build_nuclei_command("https://example.com", profile="does-not-exist")
