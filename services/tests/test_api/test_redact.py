"""Tests for the HTTP audit redaction module."""

from bamf.api.proxy.redact import redact_body, redact_headers, redact_query


class TestRedactHeaders:
    """Test redact_headers() for full, cookie, and set-cookie redaction."""

    def test_authorization_redacted(self):
        """Authorization header value is fully replaced with [REDACTED]."""
        headers = {"Authorization": "Bearer eyJhbGciOi...", "Accept": "application/json"}
        result = redact_headers(headers)
        assert result["Authorization"] == "[REDACTED]"
        assert result["Accept"] == "application/json"

    def test_proxy_authorization_redacted(self):
        """Proxy-Authorization header is fully redacted."""
        headers = {"Proxy-Authorization": "Basic dXNlcjpwYXNz"}
        result = redact_headers(headers)
        assert result["Proxy-Authorization"] == "[REDACTED]"

    def test_x_api_key_redacted(self):
        """X-Api-Key header is fully redacted."""
        headers = {"X-Api-Key": "sk-1234567890abcdef"}
        result = redact_headers(headers)
        assert result["X-Api-Key"] == "[REDACTED]"

    def test_x_auth_token_redacted(self):
        """X-Auth-Token header is fully redacted."""
        headers = {"X-Auth-Token": "tok_abc123"}
        result = redact_headers(headers)
        assert result["X-Auth-Token"] == "[REDACTED]"

    def test_all_sensitive_headers_redacted_together(self):
        """All four sensitive headers are redacted in a single call."""
        headers = {
            "Authorization": "Bearer xxx",
            "Proxy-Authorization": "Basic yyy",
            "X-Api-Key": "key-zzz",
            "X-Auth-Token": "tok-www",
            "Content-Type": "application/json",
        }
        result = redact_headers(headers)
        assert result["Authorization"] == "[REDACTED]"
        assert result["Proxy-Authorization"] == "[REDACTED]"
        assert result["X-Api-Key"] == "[REDACTED]"
        assert result["X-Auth-Token"] == "[REDACTED]"
        assert result["Content-Type"] == "application/json"

    def test_case_insensitive_matching(self):
        """Header name matching is case-insensitive."""
        headers = {
            "authorization": "Bearer lowered",
            "AUTHORIZATION": "Bearer uppered",
            "x-api-KEY": "mixed",
        }
        result = redact_headers(headers)
        assert result["authorization"] == "[REDACTED]"
        assert result["AUTHORIZATION"] == "[REDACTED]"
        assert result["x-api-KEY"] == "[REDACTED]"

    def test_non_sensitive_headers_unchanged(self):
        """Non-sensitive headers pass through without modification."""
        headers = {
            "Content-Type": "text/html",
            "Accept-Language": "en-US",
            "X-Request-Id": "abc-123",
        }
        result = redact_headers(headers)
        assert result == headers

    def test_empty_dict_returns_empty(self):
        """An empty header dict returns an empty dict."""
        assert redact_headers({}) == {}

    def test_cookie_values_redacted_names_preserved(self):
        """Cookie header: values are redacted but names are preserved."""
        headers = {"Cookie": "bamf_session=abc123; theme=dark"}
        result = redact_headers(headers)
        assert result["Cookie"] == "bamf_session=[REDACTED]; theme=[REDACTED]"

    def test_cookie_single_pair(self):
        """Cookie header with a single cookie pair."""
        headers = {"Cookie": "sid=xyz789"}
        result = redact_headers(headers)
        assert result["Cookie"] == "sid=[REDACTED]"

    def test_cookie_valueless_part_preserved(self):
        """Cookie segments without '=' are preserved as-is."""
        headers = {"Cookie": "bamf_session=abc; flagonly"}
        result = redact_headers(headers)
        assert "bamf_session=[REDACTED]" in result["Cookie"]
        assert "flagonly" in result["Cookie"]

    def test_set_cookie_value_redacted_attributes_preserved(self):
        """Set-Cookie: value portion redacted, attributes like Path and HttpOnly preserved."""
        headers = {"Set-Cookie": "bamf_session=abc123; Path=/; HttpOnly"}
        result = redact_headers(headers)
        # Implementation splits on ";" and rejoins with "; ", which adds a
        # space before the attribute's existing leading space.  Verify the
        # semantically important parts rather than exact whitespace.
        assert result["Set-Cookie"].startswith("bamf_session=[REDACTED]")
        assert "Path=/" in result["Set-Cookie"]
        assert "HttpOnly" in result["Set-Cookie"]

    def test_set_cookie_with_many_attributes(self):
        """Set-Cookie with multiple attributes preserves them all."""
        headers = {
            "Set-Cookie": "token=secret_value; Path=/api; Domain=.example.com; Secure; SameSite=Strict"
        }
        result = redact_headers(headers)
        assert result["Set-Cookie"].startswith("token=[REDACTED]")
        assert "Path=/api" in result["Set-Cookie"]
        assert "Domain=.example.com" in result["Set-Cookie"]
        assert "Secure" in result["Set-Cookie"]
        assert "SameSite=Strict" in result["Set-Cookie"]

    def test_set_cookie_no_value(self):
        """Set-Cookie with no '=' in first segment returns unchanged."""
        headers = {"Set-Cookie": "malformed; Path=/"}
        result = redact_headers(headers)
        # First segment has no '=' so it is not modified
        assert "malformed" in result["Set-Cookie"]
        assert "Path=/" in result["Set-Cookie"]

    def test_cookie_case_insensitive(self):
        """Cookie and Set-Cookie header matching is case-insensitive."""
        headers = {
            "COOKIE": "sid=val1",
            "SET-COOKIE": "sid=val2; Path=/",
        }
        result = redact_headers(headers)
        assert result["COOKIE"] == "sid=[REDACTED]"
        assert result["SET-COOKIE"].startswith("sid=[REDACTED]")


class TestRedactBodyJson:
    """Test redact_body() with application/json content type."""

    def test_password_field_redacted(self):
        """The 'password' field is redacted, others unchanged."""
        body = '{"username": "alice", "password": "s3cret"}'
        result = redact_body(body, "application/json")
        import json

        data = json.loads(result)
        assert data["username"] == "alice"
        assert data["password"] == "[REDACTED]"

    def test_nested_objects_redacted(self):
        """Sensitive fields inside nested objects are redacted."""
        import json

        body = json.dumps({"config": {"secret": "my-secret", "host": "db.local"}})
        result = redact_body(body, "application/json")
        data = json.loads(result)
        assert data["config"]["secret"] == "[REDACTED]"
        assert data["config"]["host"] == "db.local"

    def test_arrays_with_sensitive_fields(self):
        """Sensitive fields in objects inside arrays are redacted."""
        import json

        body = json.dumps(
            {
                "users": [
                    {"name": "alice", "password": "pw1"},
                    {"name": "bob", "password": "pw2"},
                ]
            }
        )
        result = redact_body(body, "application/json")
        data = json.loads(result)
        assert data["users"][0]["name"] == "alice"
        assert data["users"][0]["password"] == "[REDACTED]"
        assert data["users"][1]["name"] == "bob"
        assert data["users"][1]["password"] == "[REDACTED]"

    def test_all_redact_body_fields(self):
        """All fields in REDACT_BODY_FIELDS are redacted."""
        import json

        body = json.dumps(
            {
                "password": "pw",
                "secret": "sec",
                "client_secret": "cs",
                "code_verifier": "cv",
                "samlresponse": "sr",
                "session_token": "st",
                "key": "k",
                "private_key": "pk",
                "safe_field": "keep-me",
            }
        )
        result = redact_body(body, "application/json")
        data = json.loads(result)
        for field in [
            "password",
            "secret",
            "client_secret",
            "code_verifier",
            "samlresponse",
            "session_token",
            "key",
            "private_key",
        ]:
            assert data[field] == "[REDACTED]", f"Expected {field} to be redacted"
        assert data["safe_field"] == "keep-me"

    def test_case_insensitive_field_matching(self):
        """Field name matching is case-insensitive."""
        import json

        body = json.dumps({"Password": "hidden", "SECRET": "hidden2"})
        result = redact_body(body, "application/json")
        data = json.loads(result)
        assert data["Password"] == "[REDACTED]"
        assert data["SECRET"] == "[REDACTED]"

    def test_malformed_json_returns_unchanged(self):
        """Malformed JSON body is returned as-is without crashing."""
        body = '{"incomplete": "json'
        result = redact_body(body, "application/json")
        assert result == body

    def test_empty_body_returns_empty(self):
        """Empty body string returns empty string."""
        assert redact_body("", "application/json") == ""

    def test_content_type_with_charset(self):
        """Content-Type with charset parameter is handled correctly."""
        import json

        body = json.dumps({"password": "secret"})
        result = redact_body(body, "application/json; charset=utf-8")
        data = json.loads(result)
        assert data["password"] == "[REDACTED]"

    def test_deeply_nested_redaction(self):
        """Sensitive fields deeply nested are redacted."""
        import json

        body = json.dumps({"a": {"b": {"c": {"private_key": "deep-secret"}}}})
        result = redact_body(body, "application/json")
        data = json.loads(result)
        assert data["a"]["b"]["c"]["private_key"] == "[REDACTED]"

    def test_non_sensitive_fields_at_all_levels(self):
        """Non-sensitive fields at every nesting level are unchanged."""
        import json

        body = json.dumps({"name": "top", "inner": {"label": "mid", "items": [{"id": 1}]}})
        result = redact_body(body, "application/json")
        data = json.loads(result)
        assert data["name"] == "top"
        assert data["inner"]["label"] == "mid"
        assert data["inner"]["items"][0]["id"] == 1


class TestRedactBodyForm:
    """Test redact_body() with application/x-www-form-urlencoded content type."""

    def test_password_redacted_in_form(self):
        """Password field is redacted in URL-encoded form data."""
        body = "username=alice&password=s3cret"
        result = redact_body(body, "application/x-www-form-urlencoded")
        assert "password=%5BREDACTED%5D" in result
        assert "username=alice" in result

    def test_non_sensitive_form_fields_unchanged(self):
        """Non-sensitive form fields remain unchanged."""
        body = "name=alice&email=alice%40example.com"
        result = redact_body(body, "application/x-www-form-urlencoded")
        assert "name=alice" in result
        assert "email=alice%40example.com" in result

    def test_multiple_sensitive_form_fields(self):
        """Multiple sensitive fields are all redacted."""
        body = "password=pw&secret=sec&name=bob"
        result = redact_body(body, "application/x-www-form-urlencoded")
        assert "password=%5BREDACTED%5D" in result
        assert "secret=%5BREDACTED%5D" in result
        assert "name=bob" in result


class TestRedactBodyOtherContentTypes:
    """Test redact_body() with non-JSON, non-form content types."""

    def test_text_plain_unchanged(self):
        """text/plain body is returned unchanged."""
        body = "password=secret"
        result = redact_body(body, "text/plain")
        assert result == body

    def test_text_html_unchanged(self):
        """text/html body is returned unchanged."""
        body = "<html><body>password=secret</body></html>"
        result = redact_body(body, "text/html")
        assert result == body

    def test_application_xml_unchanged(self):
        """application/xml body is returned unchanged."""
        body = "<secret>value</secret>"
        result = redact_body(body, "application/xml")
        assert result == body

    def test_octet_stream_unchanged(self):
        """application/octet-stream body is returned unchanged."""
        body = "\x00\x01\x02password\x03"
        result = redact_body(body, "application/octet-stream")
        assert result == body


class TestRedactQuery:
    """Test redact_query() for query string parameter redaction."""

    def test_password_redacted_name_unchanged(self):
        """password param is redacted, name param passes through."""
        result = redact_query("password=secret&name=alice")
        assert "password=%5BREDACTED%5D" in result
        assert "name=alice" in result

    def test_multiple_sensitive_params(self):
        """All sensitive query params are redacted."""
        result = redact_query("password=pw&secret=sec&token=tok&api_key=ak&key=k&safe=ok")
        assert "password=%5BREDACTED%5D" in result
        assert "secret=%5BREDACTED%5D" in result
        assert "token=%5BREDACTED%5D" in result
        assert "api_key=%5BREDACTED%5D" in result
        assert "key=%5BREDACTED%5D" in result
        assert "safe=ok" in result

    def test_empty_query_returns_empty(self):
        """Empty query string returns empty string."""
        assert redact_query("") == ""

    def test_non_sensitive_params_unchanged(self):
        """Non-sensitive query parameters remain unchanged."""
        result = redact_query("page=2&limit=50&sort=name")
        assert "page=2" in result
        assert "limit=50" in result
        assert "sort=name" in result

    def test_none_query_returns_none(self):
        """None input is returned as-is (falsy check)."""
        assert redact_query(None) is None

    def test_single_sensitive_param(self):
        """A query string with only one sensitive param."""
        result = redact_query("token=abc123")
        assert result == "token=%5BREDACTED%5D"

    def test_single_non_sensitive_param(self):
        """A query string with only one non-sensitive param."""
        result = redact_query("cursor=xyz")
        assert result == "cursor=xyz"
