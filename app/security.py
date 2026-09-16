from dataclasses import dataclass


@dataclass(frozen=True)
class UntrustedSource:
    """
    Represents source code that must be treated strictly as data.

    This boundary makes the security assumption explicit:
    source-code content can be analyzed, but it cannot provide
    instructions to the review system.
    """

    filename: str
    content: str


class SourceSecurityBoundary:
    """
    Security boundary between application instructions and source code.

    The source is never interpreted as an instruction to the reviewer.
    It is only wrapped as review data.
    """

    SOURCE_START = "<source_code>"
    SOURCE_END = "</source_code>"

    def wrap(
        self,
        source: str,
        filename: str,
    ) -> UntrustedSource:
        if not isinstance(source, str):
            raise TypeError("Source code must be a string.")

        if not isinstance(filename, str):
            raise TypeError("Filename must be a string.")

        return UntrustedSource(
            filename=filename,
            content=source,
        )

    def build_review_context(
        self,
        source: str,
        filename: str,
    ) -> str:
        """
        Build a clearly delimited representation of source code.

        The delimiters are contextual markers only. They do not grant
        the source any authority over the review instructions.
        """

        untrusted_source = self.wrap(
            source=source,
            filename=filename,
        )

        return (
            f"{self.SOURCE_START} "
            f"filename={untrusted_source.filename!r}\n"
            f"{untrusted_source.content}\n"
            f"{self.SOURCE_END}"
        )