from pathlib import Path


class SourceLoader:
    """
    Loads Python source files for review.

    The loader accepts either:
    - a single Python file
    - a directory containing Python files

    Non-Python files are ignored.
    """

    def load_file(self, path: str | Path) -> tuple[str, str]:
        """
        Load a single Python source file.

        Returns:
            A tuple containing:
            - filename
            - source code
        """
        file_path = Path(path)

        if not file_path.exists():
            raise FileNotFoundError(
                f"Source path does not exist: {file_path}"
            )

        if not file_path.is_file():
            raise ValueError(
                f"Expected a file but received: {file_path}"
            )

        if file_path.suffix.lower() != ".py":
            raise ValueError(
                f"Only Python files are supported: {file_path}"
            )

        try:
            source = file_path.read_text(
                encoding="utf-8"
            )
        except OSError as exc:
            raise OSError(
                f"Unable to read source file {file_path}: {exc}"
            ) from exc

        return str(file_path), source

    def load_repository(
        self,
        path: str | Path,
    ) -> list[tuple[str, str]]:
        """
        Load all Python files from a repository directory.

        Common virtual-environment and cache directories are skipped.
        """
        root = Path(path)

        if not root.exists():
            raise FileNotFoundError(
                f"Repository path does not exist: {root}"
            )

        if not root.is_dir():
            raise ValueError(
                f"Expected a directory but received: {root}"
            )

        ignored_directories = {
            ".git",
            ".venv",
            "venv",
            "__pycache__",
            ".pytest_cache",
            "node_modules",
        }

        loaded_files: list[tuple[str, str]] = []

        for file_path in sorted(root.rglob("*.py")):
            if any(
                part in ignored_directories
                for part in file_path.parts
            ):
                continue

            try:
                source = file_path.read_text(
                    encoding="utf-8"
                )
            except (OSError, UnicodeDecodeError):
                continue

            loaded_files.append(
                (
                    str(file_path),
                    source,
                )
            )

        return loaded_files

    def load(
        self,
        path: str | Path,
    ) -> list[tuple[str, str]]:
        """
        Automatically load either one Python file or a repository.
        """
        target = Path(path)

        if target.is_file():
            return [self.load_file(target)]

        if target.is_dir():
            return self.load_repository(target)

        raise FileNotFoundError(
            f"Unable to load source path: {target}"
        )