from pc_usage_watchdog.app import ProcessSnapshot, classify_process, is_system_path


def test_system_idle_process_is_not_flagged():
    proc = ProcessSnapshot(
        pid=0,
        ppid=0,
        name="System Idle Process",
        username="NT AUTHORITY\\SYSTEM",
        cpu=999.0,
        mem_mb=0.0,
        create_time=0.0,
        exe="",
        cmdline="",
        status="running",
    )

    score, reasons = classify_process(proc)

    assert score == 0
    assert reasons == ["Windows core process"]


def test_windows_defender_platform_path_is_system_like():
    assert is_system_path(r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.0\MsMpEng.exe")


def test_temp_script_tool_is_flagged():
    proc = ProcessSnapshot(
        pid=123,
        ppid=1,
        name="cmd.exe",
        username="PC\\megha",
        cpu=1.0,
        mem_mb=10.0,
        create_time=0.0,
        exe=r"C:\Users\megha\AppData\Local\Temp\cmd.exe",
        cmdline="cmd.exe /c whoami",
        status="running",
    )

    score, reasons = classify_process(proc)

    assert score >= 40
    assert "Console/script/admin tool" in reasons
    assert "Runs from user-writable location" in reasons
