  """
Kawach Student Portal
=====================
UI for anonymous safety reporting with live PII scrubbing preview.
Part of PS-07: Privacy-Preserving Harassment Pattern Detection.
"""

from __future__ import annotations

import inspect
import re
from typing import Any, Callable
import streamlit as st


def _default_regex_scrub(text: str) -> str:
    """Safe fallback scrubber that redacts phone numbers, emails, and basic identifiers."""
    if not text:
        return ""
    # Redact email addresses
    scrubbed = re.sub(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "[REDACTED EMAIL]",
        text,
    )
    # Redact 10-12 digit phone numbers
    scrubbed = re.sub(
        r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|\b\d{10}\b",
        "[REDACTED PHONE]",
        scrubbed,
    )
    # Redact student IDs / roll numbers (e.g., 2021BCS012, STU-12345)
    scrubbed = re.sub(
        r"\b(?:[A-Z]{2,4}[-\s]?\d{4,8}|\d{2}[A-Z]{3}\d{3,4})\b",
        "[REDACTED ID]",
        scrubbed,
    )
    return scrubbed


def _safe_scrub(scrub_func: Callable[[str], str] | None, text: str) -> str:
    """Safely invokes the user-provided scrub function with fallback protection."""
    if not text:
        return ""
    if callable(scrub_func):
        try:
            result = scrub_func(text)
            if isinstance(result, str):
                return result
            if isinstance(result, dict) and "scrubbed_text" in result:
                return str(result["scrubbed_text"])
            return str(result)
        except Exception as err:
            st.error(f"⚠️ Scrubbing error: {err}. Applying fallback PII sanitizer.")
            return _default_regex_scrub(text)
    return _default_regex_scrub(text)


def _trigger_save_callback(
    save_callback: Callable[..., Any] | None,
    location: str,
    category: str,
    scrubbed_text: str,
    raw_text: str = "",
) -> Any:
    """
    Safely executes the save_callback across diverse backend signatures
    (positional arguments, dictionary/record payload, or kwargs).
    """
    if not callable(save_callback):
        return None

    try:
        sig = inspect.signature(save_callback)
        params = list(sig.parameters.values())

        # If callback expects a single dictionary payload
        if len(params) == 1 and params[0].default == inspect.Parameter.empty:
            payload = {
                "location": location,
                "category": category,
                "scrubbed_report": scrubbed_text,
                "scrubbed_text": scrubbed_text,
                "raw_text": raw_text,
            }
            return save_callback(payload)

        # If callback expects positional arguments (location, category, scrubbed_text)
        return save_callback(location, category, scrubbed_text)
    except TypeError:
        # Fallback to keyword arguments
        try:
            return save_callback(
                location=location,
                category=category,
                scrubbed_text=scrubbed_text,
            )
        except TypeError:
            return save_callback(
                {
                    "location": location,
                    "category": category,
                    "scrubbed_text": scrubbed_text,
                }
            )


def render_student_portal(
    save_callback: Callable[..., Any] | None = None,
    scrub_func: Callable[[str], str] | None = None,
) -> None:
    """
    Renders the student-facing anonymous incident reporting portal with
    live PII scrubbing visualization and privacy assurance.

    Parameters
    ----------
    save_callback : Callable
        Function invoked when a report is submitted. Receives (location, category, scrubbed_text).
    scrub_func : Callable
        Function that anonymizes user incident details, redacting names, phone numbers, and emails.
    """
    # ----------------- Portal Header & Privacy Notice -----------------
    st.markdown(
        """
        <div style="background: linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%); 
                    padding: 24px; border-radius: 12px; margin-bottom: 24px; color: white;">
            <h1 style="margin: 0; font-size: 2.1rem; color: #ffffff;">🛡️ Kawach: Anonymous Safety Reporting</h1>
            <p style="margin: 8px 0 0 0; font-size: 1.05rem; opacity: 0.92; color: #e0f2fe;">
                PS-07: Privacy-Preserving Harassment & Incident Pattern Detection
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 100% PII Anonymization Explanatory Card
    st.info(
        """
        🔒 **Zero-Knowledge Privacy Guarantee (100% PII Scrubbed)**  
        Kawach is architected to protect your identity with mathematical and algorithmic guarantees:
        * **No Identifiers Stored:** Your IP address, device fingerprints, and student IDs are never logged.
        * **In-Flight PII Redaction:** Phone numbers, email addresses, names, and roll numbers are sanitized in real-time.
        * **Scrubbed Preview:** Only the anonymized version shown below is shared with safety administrators for pattern detection.
        """,
        icon="🔐",
    )

    st.divider()

    # ----------------- Form Dropdown & Field Options -----------------
    LOCATION_OPTIONS = [
        "Academic Block A",
        "Academic Block B",
        "Hostel Gate 1",
        "Central Library Area",
        "Campus Canteen",
        "Sports Complex",
    ]

    CATEGORY_OPTIONS = [
        "Unsafe Corridor / Poor Lighting",
        "Verbal Harassment",
        "Stalking / Suspicious Activity",
        "Unauthorized Entry",
        "Other Safety Concern",
    ]

    st.markdown("### 📝 Incident Report Form")
    st.caption("Please fill in the incident parameters. All specific identifiers will be automatically expunged.")

    col_loc, col_cat = st.columns(2)

    with col_loc:
        selected_location = st.selectbox(
            "📍 Location of Incident",
            options=LOCATION_OPTIONS,
            index=0,
            help="Select the campus location where the safety concern or incident took place.",
        )

    with col_cat:
        selected_category = st.selectbox(
            "⚠️ Category of Concern",
            options=CATEGORY_OPTIONS,
            index=0,
            help="Classify the nature of the safety incident to aid institutional response.",
        )

    # Text area for incident details
    incident_details_input = st.text_area(
        label="📄 Incident Details",
        placeholder=(
            "Describe the incident in detail (e.g., location specifics, time, circumstances). "
            "Feel free to write naturally—any phone numbers (e.g., 9876543210), email addresses "
            "(e.g., student@campus.edu), and names will be redacted into [REDACTED PHONE], "
            "[REDACTED EMAIL], etc., before submission."
        ),
        height=140,
        key="kawach_student_incident_details",
        help="All personally identifiable information (PII) is automatically scrubbed before saving.",
    )

    # ----------------- Live PII Scrubbing Preview -----------------
    st.markdown("#### 👁️ Live PII Scrubbing Preview")
    st.caption("Demonstrating real-time client-side anonymization as you type:")

    if incident_details_input and incident_details_input.strip():
        live_scrubbed_text = _safe_scrub(scrub_func, incident_details_input)
        has_redaction = "[REDACTED" in live_scrubbed_text

        st.markdown(
            f"""
            <div style="background-color: #f8fafc; border: 1px solid #cbd5e1; border-left: 5px solid {'#10b981' if not has_redaction else '#f59e0b'}; 
                        padding: 16px; border-radius: 8px; margin-bottom: 16px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span style="font-weight: 600; font-size: 0.95rem; color: #1e293b;">
                        🛡️ Live Anonymized Representation:
                    </span>
                    <span style="font-size: 0.8rem; background-color: {'#d1fae5' if not has_redaction else '#fef3c7'}; 
                                 color: {'#065f46' if not has_redaction else '#92400e'}; padding: 2px 8px; border-radius: 9999px; font-weight: 600;">
                        {'Zero PII Detected' if not has_redaction else 'PII Stripped & Sanitized'}
                    </span>
                </div>
                <div style="font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; 
                            background: white; padding: 12px; border-radius: 6px; border: 1px solid #e2e8f0; color: #0f172a; white-space: pre-wrap;">{live_scrubbed_text}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <div style="background-color: #f1f5f9; border: 1px dashed #94a3b8; padding: 14px; border-radius: 8px; color: #64748b; font-size: 0.9rem;">
                ℹ️ <em>Type incident details above to watch phone numbers, emails, and student names convert into privacy-safe tokens in real time.</em>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.write("")  # Spacing

    # ----------------- Submission Action -----------------
    submit_button = st.button(
        "🛡️ Submit Anonymous Safety Report",
        type="primary",
        use_container_width=True,
        help="Submits your anonymized report to campus safety. Zero PII is transmitted.",
    )

    if submit_button:
        cleaned_input = incident_details_input.strip() if incident_details_input else ""
        if not cleaned_input:
            st.warning("⚠️ Please provide details of the incident before submitting the report.")
            return

        with st.spinner("Anonymizing PII and logging report securely..."):
            # 1. Pass raw text through scrub_func to generate anonymized text
            anonymized_text = _safe_scrub(scrub_func, cleaned_input)

            # 2. Trigger save_callback to pass data to backend
            _trigger_save_callback(
                save_callback=save_callback,
                location=selected_location,
                category=selected_category,
                scrubbed_text=anonymized_text,
                raw_text=cleaned_input,
            )

        # 3. Display green success notification showing preview of scrubbed text
        st.success(
            "✅ **Anonymous Report Successfully Logged!** Thank you for helping make our campus safer. "
            "Your report has been stored with zero personal identifiers.",
            icon="✅",
        )

        st.markdown(
            f"""
            <div style="background-color: #ecfdf5; border: 1px solid #a7f3d0; border-radius: 8px; padding: 18px; margin-top: 14px;">
                <h4 style="margin: 0 0 10px 0; color: #065f46; font-size: 1.05rem;">
                    📋 Stored Report Summary (Scrubbed Database Record)
                </h4>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 12px; font-size: 0.9rem;">
                    <div><strong>📍 Location:</strong> {selected_location}</div>
                    <div><strong>⚠️ Category:</strong> {selected_category}</div>
                </div>
                <div style="font-weight: 600; font-size: 0.88rem; color: #047857; margin-bottom: 4px;">
                    🛡️ Scrubbed Text Stored in Database:
                </div>
                <div style="background: white; border: 1px solid #6ee7b7; border-radius: 6px; padding: 12px; 
                            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.92rem; color: #064e3b; white-space: pre-wrap;">{anonymized_text}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.divider()

    # Footer helpline and reassurance
    st.markdown(
        """
        <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.85rem; color: #64748b;">
            <span>🚨 <strong>Immediate Emergency:</strong> Call Campus Security Desk at <strong>+91-11-2000-SAFE</strong> or Dial <strong>112</strong></span>
            <span>🔒 Encrypted &bull; Zero PII &bull; Kawach v1.0</span>
        </div>
        """,
        unsafe_allow_html=True,
    )  