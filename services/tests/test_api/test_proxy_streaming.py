"""Tests for streaming response detection in the HTTP proxy handler."""


class TestStreamingResponseDetection:
    """Test the heuristics used to detect streaming responses.

    The proxy handler checks Content-Type and Transfer-Encoding to
    determine whether to stream the response body or buffer it fully.
    These tests verify the detection logic in isolation.
    """

    def test_sse_content_type_detected(self):
        """text/event-stream Content-Type is detected as streaming."""
        assert _is_streaming("text/event-stream", "chunked", has_content_length=False)

    def test_sse_with_charset_detected(self):
        """text/event-stream with charset parameter is detected as streaming."""
        assert _is_streaming("text/event-stream; charset=utf-8", "", has_content_length=False)

    def test_chunked_without_content_length_detected(self):
        """Chunked transfer with no Content-Length is detected as streaming."""
        assert _is_streaming("application/json", "chunked", has_content_length=False)

    def test_chunked_with_content_length_not_streaming(self):
        """Chunked with Content-Length is not streaming (fully bufferable)."""
        assert not _is_streaming("application/json", "chunked", has_content_length=True)

    def test_json_with_content_length_not_streaming(self):
        """Normal JSON response with Content-Length is not streaming."""
        assert not _is_streaming("application/json", "", has_content_length=True)

    def test_html_not_streaming(self):
        """HTML response is not streaming."""
        assert not _is_streaming("text/html", "", has_content_length=True)

    def test_no_content_type_no_chunked_not_streaming(self):
        """No Content-Type and no chunked Transfer-Encoding is not streaming."""
        assert not _is_streaming("", "", has_content_length=False)

    def test_octet_stream_chunked_no_length_is_streaming(self):
        """Binary chunked stream without Content-Length is detected as streaming."""
        assert _is_streaming("application/octet-stream", "chunked", has_content_length=False)


def _is_streaming(content_type: str, transfer_encoding: str, *, has_content_length: bool) -> bool:
    """Reproduce the streaming detection logic from handle_proxy_request().

    This is extracted here so the test doesn't import the full handler
    with all its dependencies.
    """
    is_streaming = "text/event-stream" in content_type or (
        transfer_encoding.lower() == "chunked" and not has_content_length
    )
    return is_streaming
