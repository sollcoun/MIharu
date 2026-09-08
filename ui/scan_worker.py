from pathlib import Path

from PySide6.QtCore import QProcess

from config import APP_DATA_DIR, ensure_app_dirs


class ScanWorker:
    def __init__(self, script_path: Path, on_output, on_finished, on_error, mode: str = "Full", drives: list[str] | None = None):
        self.process = QProcess()
        self.process.setProgram("powershell.exe")
        mode = mode if mode in ("Quick", "Full") else "Full"
        drive_args = []
        for drive in drives or []:
            value = str(drive).strip().upper().rstrip("\\")
            if value and not value.endswith(":"):
                value += ":"
            if value:
                drive_args.append(value)
        # Pass drives as comma-separated for proper PowerShell array binding
        drives_param = ",".join(drive_args) if drive_args else ""
        self.process.setArguments([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
            "-Mode",
            mode,
            "-Drives",
            drives_param,
        ])

        self.process.readyReadStandardOutput.connect(
            lambda: on_output(
                bytes(self.process.readAllStandardOutput().data()).decode(
                    "utf-8",
                    errors="replace",
                )
            )
        )

        self.process.readyReadStandardError.connect(
            lambda: on_output(
                bytes(self.process.readAllStandardError().data()).decode(
                    "utf-8",
                    errors="replace",
                )
            )
        )

        self.process.finished.connect(
            lambda code, status: on_finished(code)
        )

        self.process.errorOccurred.connect(
            lambda err: on_error(str(err))
        )

    def start(self):
        ensure_app_dirs()
        env = self.process.processEnvironment()
        env.insert("DISK_DIAGNOSTIC_DATA_DIR", str(APP_DATA_DIR))
        self.process.setProcessEnvironment(env)
        self.process.start()

    def is_running(self) -> bool:
        return self.process.state() != QProcess.ProcessState.NotRunning
