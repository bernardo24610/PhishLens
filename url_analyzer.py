import socket
import ipaddress
import ssl
import requests
import tldextract

from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from requests.exceptions import RequestException


# ==========================================
# CONFIGURATION
# ==========================================

TIMEOUT = 5
MAX_PAGE_SIZE = 1_000_000
MAX_REDIRECTS = 5

HEADERS = {
    "User-Agent": "PhishLens-Security-Analyzer/1.0"
}

EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=None
)


# ==========================================
# URL NORMALIZATION
# ==========================================

def normalize_url(url):

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def get_hostname(url):

    try:
        return urlparse(url).hostname
    except Exception:
        return None


def get_registered_domain(url):

    hostname = get_hostname(url)

    if not hostname:
        return None

    result = EXTRACTOR(hostname)

    if not result.domain or not result.suffix:
        return hostname.lower()

    return f"{result.domain}.{result.suffix}".lower()


def same_domain(url1, url2):

    domain1 = get_registered_domain(url1)
    domain2 = get_registered_domain(url2)

    if not domain1 or not domain2:
        return False

    return domain1 == domain2


# ==========================================
# SAFE WEBSITE CONNECTION
# ==========================================

def is_public_host(hostname):

    if not hostname:
        return False

    try:

        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        if not addresses:
            return False

        for address in addresses:

            ip = ipaddress.ip_address(address[4][0])

            if not ip.is_global:
                return False

        return True

    except Exception:
        return False


def fetch_page(url):

    current_url = normalize_url(url)

    for _ in range(MAX_REDIRECTS + 1):

        parsed = urlparse(current_url)

        if parsed.scheme not in ("http", "https"):
            return None, None

        if parsed.port not in (None, 80, 443):
            return None, None

        hostname = parsed.hostname

        if not is_public_host(hostname):
            return None, None

        try:

            response = requests.get(
                current_url,
                headers=HEADERS,
                timeout=TIMEOUT,
                allow_redirects=False,
                stream=True,
                verify=True
            )

            if response.is_redirect:

                location = response.headers.get("Location")

                response.close()

                if not location:
                    return None, None

                current_url = urljoin(
                    current_url,
                    location
                )

                continue

            if response.status_code != 200:
                response.close()
                return None, None

            content_type = response.headers.get(
                "Content-Type", ""
            ).lower()

            if "text/html" not in content_type:
                response.close()
                return None, None

            content = bytearray()

            for chunk in response.iter_content(8192):

                content.extend(chunk)

                if len(content) > MAX_PAGE_SIZE:
                    response.close()
                    return None, None

            final_url = response.url

            response.close()

            return bytes(content), final_url

        except RequestException:
            return None, None

        except Exception:
            return None, None

    return None, None


def get_page_data(url):

    content, final_url = fetch_page(url)

    if content is None:
        return None, None, None

    try:

        soup = BeautifulSoup(
            content,
            "html.parser"
        )

        return soup, final_url, content

    except Exception:
        return None, None, None


# ==========================================
# 1. HAVING IP ADDRESS
# ==========================================

def having_ip_address(url):

    hostname = get_hostname(url)

    if not hostname:
        return None

    try:
        ipaddress.ip_address(hostname)
        return 1

    except ValueError:
        return -1


# ==========================================
# 2. URL LENGTH
# ==========================================

def get_url_length(url):

    length = len(url)

    if length < 54:
        return -1

    elif length <= 75:
        return 0

    return 1


# ==========================================
# 3. SHORTENING SERVICE
# ==========================================

def shortening_service(url):

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "ow.ly",
        "buff.ly",
        "cutt.ly",
        "goo.gl",
        "tiny.cc",
        "shorturl.at"
    ]

    hostname = get_hostname(url)

    if not hostname:
        return None

    hostname = hostname.lower()

    return 1 if hostname in shorteners else -1


# ==========================================
# 4. HAVING @ SYMBOL
# ==========================================

def having_at_symbol(url):

    return 1 if "@" in url else -1


# ==========================================
# 5. DOUBLE SLASH REDIRECTING
# ==========================================

def double_slash_redirecting(url):

    position = url.rfind("//")

    return 1 if position > 7 else -1


# ==========================================
# 6. PREFIX SUFFIX
# ==========================================

def prefix_suffix(url):

    hostname = get_hostname(url)

    if not hostname:
        return None

    return 1 if "-" in hostname else -1


# ==========================================
# 7. HAVING SUB DOMAIN
# ==========================================

def having_sub_domain(url):

    hostname = get_hostname(url)

    if not hostname:
        return None

    result = EXTRACTOR(hostname)

    if not result.domain or not result.suffix:
        return None

    subdomain = result.subdomain

    if not subdomain:
        return -1

    count = len(subdomain.split("."))

    if count == 1:
        return 0

    return 1


# ==========================================
# 8. SSL FINAL STATE
# ==========================================

def ssl_final_state(url):

    parsed = urlparse(url)

    if parsed.scheme != "https":
        return -1

    hostname = parsed.hostname

    if not hostname or not is_public_host(hostname):
        return None

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, parsed.port or 443),
            timeout=TIMEOUT
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_socket:

                cert = secure_socket.getpeercert()

                return 1 if cert else -1

    except Exception:
        return -1


# ==========================================
# 9. DOMAIN REGISTRATION LENGTH
# ==========================================

def domain_registration_length(url):

    # Requires reliable domain registration data.
    return None


# ==========================================
# 10. FAVICON
# ==========================================

def favicon(url):

    soup, final_url, _ = get_page_data(url)

    if soup is None:
        return None

    icon = soup.find(
        "link",
        rel=lambda value: value and "icon" in str(value).lower()
    )

    if not icon:
        return -1

    icon_url = icon.get("href")

    if not icon_url:
        return -1

    icon_url = urljoin(final_url, icon_url)

    return -1 if same_domain(icon_url, final_url) else 1


# ==========================================
# 11. PORT
# ==========================================

def port(url):

    parsed = urlparse(url)

    try:
        current_port = parsed.port

    except ValueError:
        return None

    if current_port is None:
        return -1

    return 1 if current_port not in (80, 443) else -1


# ==========================================
# 12. HTTPS TOKEN
# ==========================================

def https_token(url):

    hostname = get_hostname(url)

    if not hostname:
        return None

    return 1 if "https" in hostname.lower() else -1


# ==========================================
# 13. REQUEST URL
# ==========================================

def request_url(url):

    soup, final_url, _ = get_page_data(url)

    if soup is None:
        return None

    resources = []

    for tag in soup.find_all(
        ["img", "audio", "video", "script", "link"]
    ):

        source = (
            tag.get("src")
            or tag.get("href")
        )

        if source:
            resources.append(
                urljoin(final_url, source)
            )

    if not resources:
        return -1

    external = sum(
        not same_domain(resource, final_url)
        for resource in resources
    )

    percentage = external / len(resources) * 100

    return 1 if percentage > 22 else -1


# ==========================================
# 14. URL OF ANCHOR
# ==========================================

def url_of_anchor(url):

    soup, final_url, _ = get_page_data(url)

    if soup is None:
        return None

    anchors = soup.find_all("a", href=True)

    if not anchors:
        return -1

    external = 0

    for anchor in anchors:

        href = anchor.get("href")

        if not href:
            continue

        target = urljoin(final_url, href)

        if not same_domain(target, final_url):
            external += 1

    percentage = external / len(anchors) * 100

    if percentage < 31:
        return -1

    elif percentage > 67:
        return 1

    return 0


# ==========================================
# 15. LINKS IN TAGS
# ==========================================

def links_in_tags(url):

    soup, final_url, _ = get_page_data(url)

    if soup is None:
        return None

    tags = soup.find_all(["meta", "script", "link"])

    if not tags:
        return -1

    external = 0

    for tag in tags:

        target = (
            tag.get("src")
            or tag.get("href")
        )

        if target:

            target = urljoin(final_url, target)

            if not same_domain(target, final_url):
                external += 1

    percentage = external / len(tags) * 100

    if percentage < 17:
        return -1

    elif percentage > 81:
        return 1

    return 0


# ==========================================
# 16. SFH
# ==========================================

def sfh(url):

    soup, final_url, _ = get_page_data(url)

    if soup is None:
        return None

    forms = soup.find_all("form")

    if not forms:
        return -1

    for form in forms:

        action = form.get("action", "").strip()

        if not action:
            return 1

        target = urljoin(final_url, action)

        if target.startswith("mailto:"):
            return 1

        if not same_domain(target, final_url):
            return 0

    return -1


# ==========================================
# 17. SUBMITTING TO EMAIL
# ==========================================

def submitting_to_email(url):

    soup, _, _ = get_page_data(url)

    if soup is None:
        return None

    for form in soup.find_all("form"):

        action = form.get("action", "").lower()

        if "mailto:" in action:
            return 1

    return -1


# ==========================================
# 18. ABNORMAL URL
# ==========================================

def abnormal_url(url):

    # Requires reliable WHOIS/domain identity comparison.
    return None


# ==========================================
# 19. REDIRECT
# ==========================================

def redirect(url):

    # Redirect information needs a separate controlled
    # redirect measurement to match the training definition.
    return None


# ==========================================
# 20. ON MOUSEOVER
# ==========================================

def on_mouseover(url):

    soup, _, _ = get_page_data(url)

    if soup is None:
        return None

    for tag in soup.find_all(True):

        if tag.has_attr("onmouseover"):
            return 1

    return -1


# ==========================================
# 21. RIGHT CLICK
# ==========================================

def right_click(url):

    soup, _, _ = get_page_data(url)

    if soup is None:
        return None

    for tag in soup.find_all(True):

        for attribute in (
            "oncontextmenu",
            "onmousedown"
        ):

            if tag.has_attr(attribute):
                return 1

    return -1


# ==========================================
# 22. POPUP WINDOW
# ==========================================

def popup_window(url):

    soup, _, _ = get_page_data(url)

    if soup is None:
        return None

    for tag in soup.find_all("script"):

        script = tag.string or tag.get_text()

        if "window.open" in script.lower():
            return 1

    return -1


# ==========================================
# 23. IFRAME
# ==========================================

def iframe(url):

    soup, _, _ = get_page_data(url)

    if soup is None:
        return None

    return 1 if soup.find("iframe") else -1


# ==========================================
# 24. AGE OF DOMAIN
# ==========================================

def age_of_domain(url):

    # Requires reliable domain creation date.
    return None


# ==========================================
# 25. DNS RECORD
# ==========================================

def dns_record(url):

    hostname = get_hostname(url)

    if not hostname:
        return None

    try:

        socket.getaddrinfo(
            hostname,
            None
        )

        return 1

    except socket.gaierror:
        return -1

    except Exception:
        return None


# ==========================================
# 26. WEB TRAFFIC
# ==========================================

def web_traffic(url):

    # Requires a reliable traffic intelligence provider.
    return None


# ==========================================
# 27. PAGE RANK
# ==========================================

def page_rank(url):

    # Requires an external ranking data source.
    return None


# ==========================================
# 28. GOOGLE INDEX
# ==========================================

def google_index(url):

    # Requires a search index data source.
    return None


# ==========================================
# 29. LINKS POINTING TO PAGE
# ==========================================

def links_pointing_to_page(url):

    # Requires external backlink intelligence.
    return None


# ==========================================
# 30. STATISTICAL REPORT
# ==========================================

def statistical_report(url):

    # Requires an external threat intelligence source.
    return None


# ==========================================
# EXTRACT ALL 30 FEATURES
# ==========================================

def get_url_features(url):

    url = normalize_url(url)

    features = {

        "having_IP_Address": having_ip_address(url),

        "URL_Length": get_url_length(url),

        "Shortining_Service": shortening_service(url),

        "having_At_Symbol": having_at_symbol(url),

        "double_slash_redirecting": double_slash_redirecting(url),

        "Prefix_Suffix": prefix_suffix(url),

        "having_Sub_Domain": having_sub_domain(url),

        "SSLfinal_State": ssl_final_state(url),

        "Domain_registeration_length": domain_registration_length(url),

        "Favicon": favicon(url),

        "port": port(url),

        "HTTPS_token": https_token(url),

        "Request_URL": request_url(url),

        "URL_of_Anchor": url_of_anchor(url),

        "Links_in_tags": links_in_tags(url),

        "SFH": sfh(url),

        "Submitting_to_email": submitting_to_email(url),

        "Abnormal_URL": abnormal_url(url),

        "Redirect": redirect(url),

        "on_mouseover": on_mouseover(url),

        "RightClick": right_click(url),

        "popUpWidnow": popup_window(url),

        "Iframe": iframe(url),

        "age_of_domain": age_of_domain(url),

        "DNSRecord": dns_record(url),

        "web_traffic": web_traffic(url),

        "Page_Rank": page_rank(url),

        "Google_Index": google_index(url),

        "Links_pointing_to_page": links_pointing_to_page(url),

        "Statistical_report": statistical_report(url)

    }

    return features