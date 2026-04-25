"""Small compatibility shim so the package can be imported without Streamlit."""

from __future__ import annotations

try:  # pragma: no cover - import depends on local runtime packages
    import streamlit as st
    import streamlit.components.v1 as st_components
except ImportError:  # pragma: no cover - exercised in tests without Streamlit
    st = None
    st_components = None


def require_streamlit() -> None:
    """Raise a clear runtime error when Streamlit is unavailable."""

    if st is None:
        raise RuntimeError(
            "Streamlit is required to run the web app. Install it with `pip install streamlit`."
        )


def require_streamlit_components() -> None:
    """Raise a clear runtime error when Streamlit HTML components are unavailable."""

    require_streamlit()
    if st_components is None:
        raise RuntimeError(
            "Streamlit HTML components are required to render Mermaid diagrams."
        )
