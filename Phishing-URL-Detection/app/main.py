
from ipaddress import ip_address
from urllib.parse import urlsplit, parse_qsl

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


app = FastAPI(
    title="Phishing URL Detection System",
    description="A Hybrid System for Detecting Phishing URLs",
    version="1.0.0"
)


# -----------------------------
# Request and Response Schemas
# -----------------------------

class URLRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        description="URL to validate and parse"
    )


class URLAnalysisResponse(BaseModel):
    original_url: str
    normalized_url: str
    is_valid: bool
    scheme: str
    hostname: str
    port: int | None
    path: str
    query_parameters: list[dict[str, str]]
    fragment: str
    is_ip_address: bool
    has_credentials: bool


# -----------------------------
# URL Validation and Parsing
# -----------------------------

def analyze_url(url: str) -> dict:
    """
    Validate a URL and extract its main components.
    This function does not make any network requests.
    """

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    # Reject whitespace and control characters inside the URL
    if any(char.isspace() or ord(char) < 32 for char in url):
        raise ValueError("URL contains whitespace or control characters.")

    try:
        parsed = urlsplit(url)

        scheme = parsed.scheme.lower()

        if scheme not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are supported.")

        if not parsed.netloc or not parsed.hostname:
            raise ValueError("URL must contain a valid hostname.")

        hostname = parsed.hostname.lower()

        # Accessing .port also validates the port range and format
        port = parsed.port

        # Check whether hostname is an IP address
        try:
            ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

            # Basic domain/hostname validation, including IDN support
            try:
                ascii_hostname = hostname.encode("idna").decode("ascii")
            except UnicodeError:
                raise ValueError("Invalid internationalized hostname.")

            domain = ascii_hostname.rstrip(".")

            if not domain or len(domain) > 253:
                raise ValueError("Invalid hostname length.")

            labels = domain.split(".")

            for label in labels:
                if (
                    not label
                    or len(label) > 63
                    or label.startswith("-")
                    or label.endswith("-")
                    or not all(
                        char.isalnum() or char == "-"
                        for char in label
                    )
                ):
                    raise ValueError("Invalid hostname format.")

            hostname = ascii_hostname.lower()

        has_credentials = (
            parsed.username is not None
            or parsed.password is not None
        )

        # Rebuild the URL without returning embedded credentials
        if ":" in hostname:  # IPv6
            safe_hostname = f"[{hostname}]"
        else:
            safe_hostname = hostname

        default_port = (
            (scheme == "http" and port == 80)
            or (scheme == "https" and port == 443)
        )

        if port is not None and not default_port:
            safe_netloc = f"{safe_hostname}:{port}"
        else:
            safe_netloc = safe_hostname

        normalized_url = parsed._replace(
            scheme=scheme,
            netloc=safe_netloc
        ).geturl()

        query_parameters = [
            {"key": key, "value": value}
            for key, value in parse_qsl(
                parsed.query,
                keep_blank_values=True
            )
        ]

        return {
            "original_url": url,
            "normalized_url": normalized_url,
            "is_valid": True,
            "scheme": scheme,
            "hostname": hostname,
            "port": port,
            "path": parsed.path,
            "query_parameters": query_parameters,
            "fragment": parsed.fragment,
            "is_ip_address": is_ip,
            "has_credentials": has_credentials
        }

    except ValueError as error:
        raise ValueError(str(error))


# -----------------------------
# API Endpoints
# -----------------------------

@app.get("/")
def root():
    return {
        "message": "Phishing URL Detection System is running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.post("/analyze-url", response_model=URLAnalysisResponse)
def analyze_url_endpoint(request: URLRequest):

    try:
        result = analyze_url(request.url)
        return result

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )
