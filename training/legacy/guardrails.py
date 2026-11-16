"""Fail closed at legacy language-model and model-ready export boundaries."""


def block_untrusted_llm() -> None:
    raise RuntimeError(
        "Prompt-injection guard: language-model inference and model-ready exports "
        "of untrusted sample evidence are disabled. Use offline API analysis instead."
    )
