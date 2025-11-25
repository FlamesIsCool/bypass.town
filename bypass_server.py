from flask import Flask, request, render_template_string, redirect, jsonify
from flask_cors import CORS
import requests
import json
import re
from urllib.parse import urlparse, urljoin, quote_plus, urlencode
import base64
import asyncio
from playwright.async_api import async_playwright

app = Flask(__name__)
CORS(app)

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except Exception:
    BS4_AVAILABLE = False

app = Flask(__name__)

with open("bypass_town.html", "r", encoding="utf-8") as f:
    HTML_TEMPLATE = f.read()

def extract_code_from_url(url: str) -> str:
    """Extracts the last path segment or known query param code"""
    if "/s2u/" in url:
        return url.split("/s2u/")[-1].split("?")[0]
    if "code=" in url:
        return url.split("code=")[-1].split("&")[0]
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    return path.split("/")[-1] if path else url.strip()

def normalize_link_for_detection(link: str) -> str:
    return (link or "").strip().lower()

def bypass_ytsubme(code: str):
    try:
        res = requests.get(
            "https://www.ytsubme.com/dashboard/api/s2u_links.php",
            params={"mode": "s2uGetLink", "code": code},
            timeout=12,
        )
        data = res.json()
    except Exception as e:
        return None, f"❌ ytsubme error: {e}"
    if data.get("response_code") != 1:
        return None, "❌ Invalid or expired ytsubme code."
    try:
        inner = json.loads(data["msg"]["data"])
        return inner.get("targeturl"), None
    except Exception as e:
        return None, f"❌ Parsing error: {e}"

UNLOCKNOW_BASE = "https://unlocknow.net/back_end/get_linkvertise"
def extract_link_id(unlocknow_url: str) -> str:
    parsed = urlparse(unlocknow_url)
    path = parsed.path.strip("/")
    return path.split("/")[-1] if path else ""
def bypass_unlocknow(link: str):
    link_id = extract_link_id(link)
    if not link_id:
        return None, "❌ Could not extract link id from unlocknow URL."
    try:
        res = requests.post(UNLOCKNOW_BASE, json={"linkId": link_id}, timeout=12)
        data = res.json()
    except Exception as e:
        return None, f"❌ unlocknow request error: {e}"
    if isinstance(data, dict) and data.get("link"):
        return data["link"], None
    if isinstance(data, dict):
        for key in ("data", "result", "link"):
            v = data.get(key)
            if isinstance(v, str) and v:
                return v, None
            if isinstance(v, dict) and v.get("link"):
                return v["link"], None
    return None, "❌ unlocknow did not return a link."

def extract_subfinal_code(subfinal_url: str) -> str:
    parsed = urlparse(subfinal_url)
    path = parsed.path.strip("/")
    return path.split("/")[-1] if path else ""
def bypass_subfinal(link: str):
    code = extract_subfinal_code(link)
    if not code:
        return None, "❌ Could not extract SubFinal code."
    final_url = f"https://subfinal.com/final.php?$={code}&rf="
    try:
        res = requests.get(final_url, allow_redirects=True, timeout=12)
        if res.ok and res.url:
            return res.url, None
        return None, "❌ SubFinal failed to unlock or returned non-200 status."
    except Exception as e:
        return None, f"❌ SubFinal request error: {e}"

def bypass_sub2unlock(code_or_url: str):
    if not BS4_AVAILABLE:
        return None, "❌ BeautifulSoup (bs4) not installed. Install with: pip install beautifulsoup4"
    if code_or_url.startswith("http"):
        url = code_or_url
    else:
        url = f"https://sub2unlock.net/{code_or_url}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0 Safari/537.36"
    }
    try:
        r = requests.get(url, headers=headers, timeout=12)
        r.raise_for_status()
    except Exception as e:
        return None, f"❌ Error fetching Sub2Unlock page: {e}"
    try:
        soup = BeautifulSoup(r.text, "html.parser")
    except Exception as e:
        return None, f"❌ BeautifulSoup parse error: {e}"
    for id_name in ("theLinkID", "theGetLink"):
        el = soup.find(id=id_name)
        if el and el.text.strip():
            return el.text.strip(), None
    a = soup.select_one("a.getlink[href]")
    if a and a.get("href") and a["href"].strip() != "#":
        return urljoin(url, a["href"].strip()), None
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if any(domain in href for domain in ("youtube.com", "youtu.be", "bypass.vip", "http")):
            return urljoin(url, href), None
    return None, "❌ Could not extract final link from Sub2Unlock."

def bypass_sub4unlock(code_or_link: str):
    if not PLAYWRIGHT_AVAILABLE:
        return None, "❌ Playwright not installed or not available. Install with: pip install playwright && playwright install"
    parsed = urlparse(code_or_link)
    code = parsed.path.strip("/").split("/")[-1] if parsed.path else code_or_link
    url = f"https://sub4unlock.io/{code}"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            page.goto(url, wait_until="load", timeout=60000)
            try:
                tasks = page.query_selector_all("a.locked-action-link")
                for task in tasks:
                    try:
                        task.click()
                        page.wait_for_timeout(800)
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                page.wait_for_selector("a.get-link:not(.disabled)", timeout=15000)
            except Exception:
                try:
                    page.wait_for_selector("a.get-link", timeout=8000)
                except Exception:
                    browser.close()
                    return None, "❌ Sub4Unlock: get-link button did not become available."
            link_elem = page.query_selector("a.get-link")
            final_url = link_elem.get_attribute("href") if link_elem else None
            browser.close()
            if final_url:
                return final_url, None
            return None, "❌ Sub4Unlock: Could not extract final link."
    except Exception as e:
        return None, f"❌ Sub4Unlock runtime error: {e}"

def extract_rekonise_code(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    return path.split("/")[-1] if path else ""
def bypass_rekonise(link_or_code: str):
    code = link_or_code
    if link_or_code.startswith("http"):
        code = extract_rekonise_code(link_or_code)
    api_url = f"https://api.rekonise.com/social-unlocks/{code}/unlock"
    headers = {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/119.0 Safari/537.36"
    }
    try:
        r = requests.get(api_url, headers=headers, timeout=10)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return None, f"❌ Rekonise request error: {e}"
    final_link = None
    if isinstance(data, dict):
        final_link = data.get("url") or data.get("targetUrl") or data.get("link")
    if final_link:
        return final_link, None
    return None, "❌ Rekonise did not return a final link."

def bypass_paste_drop(url: str):
    """
    Extract paste slug from /paste/<slug> and return the paste content (span
    """

    m = re.search(r"/paste/([\w\d]+)", url)
    if not m:
        return None, "[!] Invalid paste-drop link: can't extract slug"
    slug = m.group(1)
    full = f"https://paste-drop.com/paste/{slug}"
    try:
        r = requests.get(full, timeout=12)
        r.raise_for_status()
    except Exception as e:
        return None, f"[!] Error fetching paste-drop page: {e}"
    if not BS4_AVAILABLE:
        return None, "❌ BeautifulSoup (bs4) not installed. Install with: pip install beautifulsoup4"
    try:
        soup = BeautifulSoup(r.text, "html.parser")
        content = soup.find("span", {"id": "content"})
        if content and content.text.strip():
            return content.text.strip(), None
        return None, "[!] Paste not found"
    except Exception as e:
        return None, f"[!] Parse error: {e}"

def bypass_mboost(link: str):
    """
    Bypass mboost.me / api.mboost.me links.
    Returns (final_url, None) on success or (None, error_msg) on failure.
    """
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})
    debug = {}
    candidates = []

    slug = link.rstrip("/").split("/")[-1]

    try:
        api_url = "https://api.mboost.me/page"
        r = session.post(api_url, json={"pageId": slug}, timeout=8)
        jr = r.json()
        debug["api_response"] = str(jr)[:800]

        if isinstance(jr, dict):
            if "targetUrl" in jr and jr["targetUrl"]:
                candidates.append(jr["targetUrl"])
            elif "data" in jr and isinstance(jr["data"], dict) and jr["data"].get("targetUrl"):
                candidates.append(jr["data"]["targetUrl"])

            if jr.get("captcha") or jr.get("requiresCaptcha"):
                return None, "❌ mboost: captcha required (api response indicated captcha)."
    except Exception as e:
        debug["api_error"] = str(e)

    if not candidates:
        try:
            unlock_url = f"https://api.mboost.me/social-unlocks/{slug}/unlock"
            r = session.get(unlock_url, timeout=8)
            jr = r.json()
            debug["unlock_response"] = str(jr)[:800]
            if isinstance(jr, dict) and jr.get("targetUrl"):
                candidates.append(jr["targetUrl"])
            elif isinstance(jr, dict) and isinstance(jr.get("data"), dict) and jr["data"].get("targetUrl"):
                candidates.append(jr["data"]["targetUrl"])
        except Exception as e:
            debug["unlock_error"] = str(e)

    if not candidates:
        try:
            r = session.get(link, timeout=8)
            html = r.text
            m = re.search(r'"targetUrl"\s*:\s*"([^"]+)"', html)
            if m:
                extracted = m.group(1).replace("\\/", "/")
                candidates.append(extracted)
                debug["regex_match"] = extracted
        except Exception as e:
            debug["html_error"] = str(e)

    if candidates:
        final = candidates[0]

        if final.startswith("//"):
            final = "https:" + final
        return final, None

    dbg_str = "; ".join(f"{k}={v}" for k, v in debug.items())
    return None, f"❌ mboost: could not extract final link. debug: {dbg_str[:800]}"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/138.0.7204.23 Safari/537.36"
)

def fetch_html(url, timeout=15):
    headers = {"User-Agent": USER_AGENT}
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.text

def bypass_boost(url: str):
    """
    Bypass Boost-like services (boost.ink, bst.gg, booo.st, bst.wtf, etc).
    Returns (final_url, None) on success or (None, error_msg) on failure.
    """
    try:
        html = fetch_html(url)

        m = re.search(r'bufpsvdhmjybvgfncqfa\s*=\s*"(.*?)"', html)
        if m:
            try:
                decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
                if decoded.startswith("http"):
                    return decoded, None
            except Exception:
                pass

        soup = BeautifulSoup(html, "html.parser")
        candidates = [a.get("href") for a in soup.select(".step_block[href]") if a.get("href")]
        if candidates:
            return candidates[0], None

        return None, "❌ boost: could not extract final link"
    except Exception as e:
        return None, f"❌ boost error: {e}"

BITLY_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
REQUEST_TIMEOUT = 12

def _extract_meta_final(html, base_url):
    """Look for canonical / og:url / meta refresh as fallback."""
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return None

    link = soup.find("link", rel="canonical")
    if link and link.get("href"):
        return urljoin(base_url, link["href"].strip())

    og = soup.find("meta", property="og:url")
    if og and og.get("content"):
        return urljoin(base_url, og["content"].strip())

    meta = soup.find("meta", attrs={"http-equiv": "refresh"})
    if meta and meta.get("content"):

        m = re.search(r'url=(.+)', meta["content"], flags=re.IGNORECASE)
        if m:
            return urljoin(base_url, m.group(1).strip().strip("'\""))

    return None

def bypass_bitly(link: str):
    """
    Best-effort unshorten for Bitly-like short links (bit.ly, j.mp, bitly.com).
    Returns (final_url, None) or (None, error_msg).
    """
    session = requests.Session()
    session.headers.update({"User-Agent": BITLY_USER_AGENT, "Accept": "*/*"})

    link = link.strip()

    try:
        r = session.head(link, allow_redirects=False, timeout=REQUEST_TIMEOUT)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location")
            if loc:

                final = urljoin(link, loc)
                return final, None

    except requests.RequestException as e:

        head_err = str(e)
    else:
        head_err = None

    try:
        r = session.get(link, allow_redirects=True, timeout=REQUEST_TIMEOUT)

        if r.history:

            return r.url, None

        final_from_meta = _extract_meta_final(r.text, r.url)
        if final_from_meta:
            return final_from_meta, None

        try:
            j = r.json()

            if isinstance(j, dict):
                for field in ("long_url", "longUrl", "url", "longUrl"):
                    if field in j and isinstance(j[field], str):
                        return j[field], None
        except Exception:
            pass

        err_msg = "Could not resolve redirects."
        if head_err:
            err_msg += f" head_error={head_err}"

        if r.url and not any(d in r.url.lower() for d in ("bit.ly", "j.mp", "bitly.com")):
            return r.url, None

        return None, "❌ bitly: unable to unshorten automatically. Try supplying a Bitly access token for API-backed expand."
    except requests.RequestException as e:
        return None, f"❌ bitly request error: {e}"

def bypass_pastebin(link: str, max_chars: int = 2000, max_lines: int = 50):
    """
    Fetch a Pastebin paste and return a preview plus the raw URL.
    Returns (result_obj, None) on success where result_obj is a dict:
      {"type":"pastebin","preview": "...", "full_url":"https://pastebin.com/raw/<id>", "raw_text": "<partial or full text>"}
    or (None, error_message) on failure.
    """
    if not link:
        return None, "❌ Empty Pastebin link."
    try:
        parsed = urlparse(link)
        path = (parsed.path or "").lstrip("/")
        if not path:
            return None, "❌ Could not extract paste id from Pastebin URL."

        if path.startswith("raw/"):
            paste_id = path.split("/", 1)[1]
        else:
            paste_id = path.split("/")[-1]

        raw_url = f"https://pastebin.com/raw/{paste_id}"
    except Exception as e:
        return None, f"❌ Invalid Pastebin URL: {e}"

    try:
        headers = {"User-Agent": USER_AGENT}
        with requests.get(raw_url, headers=headers, timeout=12, stream=True) as r:
            r.raise_for_status()
            chunks = []
            read_chars = 0

            for chunk in r.iter_content(chunk_size=1024):
                if not chunk:
                    continue
                try:
                    piece = chunk.decode("utf-8", errors="replace")
                except Exception:
                    piece = str(chunk)
                chunks.append(piece)
                read_chars += len(piece)

                if read_chars >= max_chars + 1024:
                    break
            full_text = "".join(chunks)
    except requests.RequestException as e:
        return None, f"❌ Pastebin fetch error: {e}"
    except Exception as e:
        return None, f"❌ Pastebin error: {e}"

    if not full_text:
        return None, "❌ Paste appears empty or unavailable."

    lines = full_text.splitlines()
    truncated = False
    if len(lines) > max_lines:
        preview_lines = lines[:max_lines]
        truncated = True
    else:
        preview_lines = lines

    preview = "\n".join(preview_lines)
    if len(preview) > max_chars:
        preview = preview[:max_chars]
        truncated = True

    if truncated:
        preview = preview.rstrip("\n") + "\n\n... (truncated) ..."

    result = {
        "type": "pastebin",
        "preview": preview,
        "full_url": raw_url,

        "raw_text": full_text if len(full_text) <= max_chars * 2 else full_text[: max_chars * 2],
    }
    return result, None

import re
from urllib.parse import urlparse, urljoin

def bypass_adfoc(link: str):
    """
    Robust AdFoc.us bypass:
      - GET page
      - POST /serve/credit with key (if present)
      - Re-GET page
      - Try many strategies (a.skip, click_url JS var, iframe content, meta/og)
    Returns (final_url, None) on success, or (None, debug_msg) on failure.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    debug = {}

    try:
        r = session.get(link, timeout=12)
        r.raise_for_status()
        html = r.text
        debug["initial_status"] = r.status_code
    except Exception as e:
        return None, f"❌ adfoc: initial fetch failed: {e}"

    def meta_fallback(html_text, base_url):
        try:
            if BS4_AVAILABLE:
                soup = BeautifulSoup(html_text, "html.parser")

                c = soup.find("link", rel="canonical")
                if c and c.get("href"):
                    return urljoin(base_url, c["href"].strip())
                og = soup.find("meta", property="og:url")
                if og and og.get("content"):
                    return urljoin(base_url, og["content"].strip())
                meta = soup.find("meta", attrs={"http-equiv": "refresh"})
                if meta and meta.get("content"):
                    m = re.search(r'url=(.+)', meta["content"], flags=re.IGNORECASE)
                    if m:
                        return urljoin(base_url, m.group(1).strip().strip("'\""))
        except Exception:
            pass
        return None

    base = "{scheme}://{netloc}".format(scheme=urlparse(link).scheme or "https",
                                         netloc=urlparse(link).netloc)

    try:
        if "id=\"my_key\"" in html or "id='my_key'" in html or "name=\"key\"" in html:

            mkey = None
            try:
                if BS4_AVAILABLE:
                    soup = BeautifulSoup(html, "html.parser")
                    k = soup.find(id="my_key")
                    if k and k.get("value"):
                        mkey = k["value"]
                if not mkey:
                    m = re.search(r'id=["\']my_key["\']\s+value=["\']([^"\']+)["\']', html)
                    if m:
                        mkey = m.group(1)
                if mkey:
                    credit_url = urljoin(base, "/serve/credit")

                    session.headers.update({"Referer": link})
                    ses_res = session.post(credit_url, data={"key": mkey}, timeout=8)
                    debug["serve_credit_status"] = getattr(ses_res, "status_code", None)

                    r2 = session.get(link, timeout=10)
                    r2.raise_for_status()
                    html = r2.text
                    debug["refetch_after_credit"] = r2.status_code
            except Exception as e:
                debug["serve_credit_error"] = str(e)
    except Exception:
        pass

    try:
        if BS4_AVAILABLE:
            soup = BeautifulSoup(html, "html.parser")
            a = soup.select_one("a.skip[href]")
            if a and a.get("href"):
                href = a["href"].strip()
                final = urljoin(link, href)
                return final, None
    except Exception as e:
        debug["skip_parse_error"] = str(e)

    m = re.search(r'click_url\s*=\s*["\']([^"\']+)["\']', html)
    if m:
        candidate = m.group(1)
        return urljoin(link, candidate), None

    try:
        if BS4_AVAILABLE:
            soup = BeautifulSoup(html, "html.parser")
            iframe = soup.select_one("#interstitial iframe[src], iframe[src]")
            if iframe and iframe.get("src"):
                iframe_src = iframe["src"].strip()
                iframe_url = urljoin(link, iframe_src)
                debug["iframe_src"] = iframe_url
                try:

                    ir = session.get(iframe_url, allow_redirects=True, timeout=12)
                    debug["iframe_status"] = ir.status_code

                    if ir.history:

                        return ir.url, None

                    iframe_html = ir.text
                    if BS4_AVAILABLE:
                        isoup = BeautifulSoup(iframe_html, "html.parser")

                        ia = isoup.select_one("a.skip[href], a[target][href], a[href*='http']")
                        if ia and ia.get("href"):
                            return urljoin(iframe_url, ia["href"].strip()), None

                    m2 = re.search(r'click_url\s*=\s*["\']([^"\']+)["\']', iframe_html)
                    if m2:
                        return urljoin(iframe_url, m2.group(1)), None
                    meta_try = meta_fallback(iframe_html, iframe_url)
                    if meta_try:
                        return meta_try, None
                except Exception as ie:
                    debug["iframe_fetch_error"] = str(ie)
    except Exception as e:
        debug["iframe_parse_error"] = str(e)

    m3 = re.search(r'href=["\'](https?://[^"\']+)["\'][^>]*class=["\']skip', html, flags=re.IGNORECASE)
    if m3:
        return m3.group(1), None

    meta_try = meta_fallback(html, link)
    if meta_try:
        return meta_try, None

    dbg = "; ".join(f"{k}={v}" for k, v in debug.items())

    dbg = (dbg[:1000] + "...") if len(dbg) > 1000 else dbg
    return None, f"❌ adfoc: could not extract skip/final link. debug: {dbg}"

def bypass_justpaste_it(link: str, max_chars: int = 2000, max_lines: int = 50):
    """
    Fetches and parses the main content from a JustPaste.it page.
    Returns a dict similar to pastebin:
      {'type': 'justpaste', 'preview': '...', 'full_url': link, 'raw_text': '...'}
    """
    if not link:
        return None, "❌ Empty JustPaste.it link."

    try:
        headers = {"User-Agent": USER_AGENT}
        r = requests.get(link, headers=headers, timeout=12)
        r.raise_for_status()
    except requests.RequestException as e:
        return None, f"❌ Network error fetching JustPaste.it: {e}"

    try:
        soup = BeautifulSoup(r.text, "html.parser")

        title_tag = soup.find("h1", class_="articleFirstTitle")
        title_text = title_tag.get_text(strip=True) if title_tag else "(untitled)"

        article = soup.find("div", id="articleContent")
        if not article:
            return None, "❌ Could not find article content."

        raw_text = article.get_text(separator="\n", strip=True)
        if not raw_text:
            return None, "❌ Empty paste content."

        lines = raw_text.splitlines()
        truncated = False
        if len(lines) > max_lines:
            lines = lines[:max_lines]
            truncated = True

        preview = "\n".join(lines)
        if len(preview) > max_chars:
            preview = preview[:max_chars]
            truncated = True

        if truncated:
            preview += "\n\n... (truncated) ..."

        result = {
            "type": "justpaste",
            "title": title_text,
            "preview": preview,
            "full_url": link,
            "raw_text": raw_text,
        }
        return result, None

    except Exception as e:
        return None, f"❌ Parsing error: {e}"

import requests
import re
import json
from urllib.parse import urlparse

def try_cejpa_for_destination(username: str, locker_id: str):
    """
    Try to POST to cejpa.com/api/event and see if the server returns a destination in the response.
    Returns destination_url or None.
    """
    cj_url = "https://cejpa.com/api/event"
    payload = {
        "n": "locker_unlocks",
        "u": f"https://bstshrt.com/{username}/{locker_id}",
        "d": "bstshrt.com",
        "r": None,
        "p": {
            "unlocker_id": locker_id,
            "unlocker_title": None,
            "creator": username,
        },
    }
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json;charset=UTF-8",
        "Origin": "https://bstshrt.com",
        "Referer": f"https://bstshrt.com/{username}/{locker_id}",
    }
    try:
        resp = requests.post(cj_url, headers=headers, json=payload, timeout=8)

        if resp.status_code in (200, 201) and resp.headers.get("content-type", "").lower().startswith("application/json"):
            try:
                j = resp.json()

                for k in ("destination_url", "destinationUrl", "destination"):
                    if k in j and isinstance(j[k], str) and j[k].startswith("http"):
                        return j[k]

                if isinstance(j.get("data"), dict):
                    for k in ("destination_url", "destinationUrl", "destination"):
                        if k in j["data"] and isinstance(j["data"][k], str):
                            return j["data"][k]
            except Exception:
                pass

        if resp.text:
            m = re.search(r'"destination[_]?url"\s*:\s*"(https?://[^"]+)"', resp.text, re.IGNORECASE)
            if m:
                return m.group(1)
        return None
    except Exception:
        return None

def bypass_bstshrt(link: str):
    """
    1) Try cejpa analytics POST to see if it returns the destination.
    2) If that fails, fall back to extracting destination from BSTSHRT page HTML.
    Returns (final_url, None) or (None, error_msg)
    """

    parsed = urlparse(link)
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2:
        return None, "❌ BSTSHRT: invalid link structure."
    username, locker_id = parts[-2], parts[-1]

    dest = try_cejpa_for_destination(username, locker_id)
    if dest:
        return dest, None

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": link,
    }
    try:
        r = requests.get(link, headers=headers, timeout=12)
        r.raise_for_status()
        html = r.text

        m = re.search(r'"destinationUrl"\s*:\s*"(https?://[^"]+)"', html)
        if not m:
            m = re.search(r'"destination_url"\s*:\s*"(https?://[^"]+)"', html)
        if not m:

            patt = re.compile(r'(https?://[^\s\'"<>\\,}]+)', re.IGNORECASE)
            for mm in patt.finditer(html):
                url = mm.group(1)
                start = max(0, mm.start() - 300)
                end = min(len(html), mm.end() + 300)
                window = html[start:end].lower()
                if "unlocker" in window or "destination" in window or "unlockerdata" in window:
                    if not any(bad in url for bad in ("googlesyndication.com","pagead2.googlesyndication.com","doubleclick.net")):
                        return url, None
        else:
            dest = m.group(1)
            return dest, None

        return None, "❌ BSTSHRT: could not extract destination from cejpa or page HTML."

    except Exception as e:
        return None, f"❌ BSTSHRT error fetching page: {e}"

def bypass_link_unlock(link: str):
    """
    Fully functional Link-Unlock bypass.
    Works with their real API:
      1) GET /u/<code>
      2) GET /auth/csrf-token
      3) POST /u/<code>/complete
    """
    try:
        code = link.strip("/").split("/")[-1]
        if not code:
            return None, "❌ LINK-UNLOCK: invalid link structure."

        session = requests.Session()
        session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Referer": link,
            "Origin": "https://link-unlock.com",
        })

        meta_url = f"https://api.link-unlock.com/u/{code}"
        r_meta = session.get(meta_url, timeout=10)
        r_meta.raise_for_status()
        meta = r_meta.json()

        if not meta.get("success") or "unlock" not in meta:
            return None, "❌ LINK-UNLOCK: invalid response from /u/<code>."
        unlock = meta["unlock"]

        steps = [s.get("id") for s in unlock.get("steps", []) if isinstance(s, dict) and s.get("id")]
        if not steps:
            return None, "❌ LINK-UNLOCK: no steps found to complete."

        token_res = session.get("https://api.link-unlock.com/auth/csrf-token", timeout=10)
        token_res.raise_for_status()
        token_data = token_res.json()
        csrf_token = token_data.get("csrfToken") or token_data.get("csrf_token")
        if not csrf_token:
            return None, "❌ LINK-UNLOCK: could not retrieve CSRF token."

        complete_url = f"https://api.link-unlock.com/u/{code}/complete"
        payload = {"steps": steps}
        session.headers["x-csrf-token"] = csrf_token
        r_complete = session.post(complete_url, json=payload, timeout=10)
        r_complete.raise_for_status()

        data = r_complete.json()

        for key in ("redirectUrl", "url", "targetUrl", "destinationUrl"):
            if key in data and isinstance(data[key], str) and data[key].startswith("http"):
                return data[key], None

        if "unlock" in data and isinstance(data["unlock"], dict):
            for key in ("redirectUrl", "url", "targetUrl", "destinationUrl"):
                if key in data["unlock"] and str(data["unlock"][key]).startswith("http"):
                    return data["unlock"][key], None

        return None, "❌ LINK-UNLOCK: could not find destination link in response."

    except Exception as e:
        return None, f"❌ LINK-UNLOCK error: {e}"

from flask import jsonify

def _success(data):
    return jsonify({"success": True, "data": data}), 200

def _error(msg):
    return jsonify({"success": False, "error": msg}), 400

def register_bypass_routes(app, namespace):
    """
    Automatically register Flask routes for all functions that start with 'bypass_'.
    Example: bypass_ytsubme -> /api/ytsubme
    """
    for name, func in namespace.items():
        if name.startswith("bypass_") and callable(func):
            route_name = name.replace("bypass_", "")
            endpoint = f"/api/{route_name}"

            def make_route(f):
                def route_func():
                    data = request.get_json(silent=True) or {}
                    link = (data.get("link") or data.get("url") or "").strip()
                    if not link:
                        return _error("❌ Missing link.")
                    try:
                        result, error = f(link)
                        if error:
                            return _error(error)
                        return _success(result)
                    except Exception as e:
                        return _error(f"❌ Internal error: {e}")
                route_func.__name__ = f"api_{route_name}"
                app.route(endpoint, methods=["POST"])(route_func)

            make_route(func)

    print("✅ Auto-registered bypass routes for:")
    for name in namespace:
        if name.startswith("bypass_"):
            print("  • /api/" + name.replace("bypass_", ""))

def bypass_isgd(link: str):
    """
    Unshorten an is.gd URL by reading the Location header (no redirect follow).
    Returns (final_url, None) on success, or (None, error_msg).
    """
    if not link:
        return None, "❌ Empty is.gd link."

    if not link.startswith("http"):
        link = "https://" + link

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Referer": "https://is.gd/"
    }

    try:

        res = requests.get(link, headers=headers, allow_redirects=False, timeout=10)
    except Exception as e:
        return None, f"❌ is.gd request error: {e}"

    if res.status_code in (301, 302, 303, 307, 308):
        target = res.headers.get("Location")
        if target:
            return target.strip(), None

    html = res.text or ""
    if BS4_AVAILABLE:
        try:
            soup = BeautifulSoup(html, "html.parser")
            div = soup.find("div", id="origurl")
            if div and "goes to:" in div.text:
                m = re.search(r'goes to:\s*(https?://\S+)', div.text)
                if m:
                    return m.group(1).strip(), None
        except Exception:
            pass

    m = re.search(r'Your shortened URL goes to:\s*(https?://[^\s"<]+)', html)
    if m:
        return m.group(1).strip(), None

    return None, "❌ is.gd: could not extract original URL (no redirect or visible origin)."

def bypass_rebrandly(link: str):
    """
    Unshorten a rebrand.ly link and return the destination URL.
    Strategies (in order):
      1) HEAD GET with allow_redirects=False -> Location header
      2) GET page and look for JSON or HTML markers (og:url, meta refresh, divs, inline JSON)
      3) Regex fallback searching for https://... near 'destination'/'destinationUrl' words
    Returns (final_url, None) or (None, error_msg).
    """
    if not link:
        return None, "❌ Empty rebrand.ly link."

    if not link.startswith("http"):
        link = "https://" + link

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": "https://rebrand.ly/"
    }

    try:
        r = requests.head(link, headers=headers, allow_redirects=False, timeout=10)
    except Exception:
        r = None

    try:
        if r is not None and r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location")
            if loc:
                return loc.strip(), None
    except Exception:
        pass

    try:
        res = requests.get(link, headers=headers, allow_redirects=False, timeout=10)
    except Exception as e:
        return None, f"❌ rebrand.ly request error: {e}"

    if res.status_code in (301, 302, 303, 307, 308):
        loc = res.headers.get("Location")
        if loc:
            return loc.strip(), None

    html = res.text or ""

    if BS4_AVAILABLE:
        try:
            soup = BeautifulSoup(html, "html.parser")

            link_tag = soup.find("link", rel="canonical")
            if link_tag and link_tag.get("href"):
                href = link_tag["href"].strip()

                if href and not href.endswith(link.split("/")[-1]):
                    return href, None

            og = soup.find("meta", property="og:url")
            if og and og.get("content"):
                return og["content"].strip(), None

            meta = soup.find("meta", attrs={"http-equiv": "refresh"})
            if meta and meta.get("content"):
                m = re.search(r'url=(.+)', meta["content"], flags=re.IGNORECASE)
                if m:
                    return m.group(1).strip().strip("'\""), None

            for script in soup.find_all("script"):
                txt = (script.string or "") if script else ""
                if "destination" in txt or "destinationUrl" in txt or "destination_url" in txt:
                    m = re.search(r'(https?://[^\s"\'<>{}\)]+)', txt)
                    if m:
                        return m.group(1).strip(), None

        except Exception:
            pass

    m = re.search(r'"destination"\s*:\s*"([^"]+)"', html)
    if not m:
        m = re.search(r'"destinationUrl"\s*:\s*"([^"]+)"', html, flags=re.IGNORECASE)
    if not m:
        m = re.search(r'destination_url["\']?\s*[:=]\s*["\'](https?://[^"\']+)["\']', html, flags=re.IGNORECASE)
    if m:
        return m.group(1).strip(), None

    lower = html.lower()
    for keyword in ("destination", "destinationurl", "target", "redirect"):
        for idx in [m.start() for m in re.finditer(keyword, lower)]:
            start = max(0, idx - 300)
            end = min(len(html), idx + 300)
            window = html[start:end]
            mm = re.search(r'(https?://[^\s"\'<>{}\)]+)', window)
            if mm:
                return mm.group(1).strip(), None

    try:
        r2 = requests.get(link, headers=headers, allow_redirects=True, timeout=10)
        final = getattr(r2, "url", None)
        if final and final != link:
            return final, None
    except Exception:
        pass

    return None, "❌ rebrand.ly: could not extract original URL."

def bypass_shorterme(link: str):
    """
    Unshorten a shorter.me link and return the destination URL.
    Strategies (in order):
      1) HEAD/GET without redirects -> Location header
      2) Parse HTML (canonical / og:url / meta refresh / inline JSON)
      3) Keyword-based regex window search
      4) Final fallback: allow redirects and return final URL
    Returns (final_url, None) or (None, error_msg).
    """
    if not link:
        return None, "❌ Empty shorter.me link."

    if not link.startswith("http"):
        link = "https://" + link

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": "https://shorter.me/"
    }

    try:
        try:
            r = requests.head(link, headers=headers, allow_redirects=False, timeout=8)
        except Exception:
            r = None

        if r is not None and r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location")
            if loc:
                return loc.strip(), None
    except Exception:
        pass

    try:
        res = requests.get(link, headers=headers, allow_redirects=False, timeout=10)
    except Exception as e:
        return None, f"❌ shorter.me request error: {e}"

    if res.status_code in (301, 302, 303, 307, 308):
        loc = res.headers.get("Location")
        if loc:
            return loc.strip(), None

    html = res.text or ""

    if BS4_AVAILABLE:
        try:
            soup = BeautifulSoup(html, "html.parser")

            c = soup.find("link", rel="canonical")
            if c and c.get("href"):
                href = c["href"].strip()
                if href and href != link:
                    return href, None

            og = soup.find("meta", property="og:url")
            if og and og.get("content"):
                return og["content"].strip(), None

            meta = soup.find("meta", attrs={"http-equiv": "refresh"})
            if meta and meta.get("content"):
                m = re.search(r'url=(.+)', meta["content"], flags=re.IGNORECASE)
                if m:
                    return m.group(1).strip().strip("'\""), None

            for script in soup.find_all("script"):
                txt = script.string or ""
                if not txt:
                    continue
                if any(k in txt for k in ("destination", "destinationUrl", "redirect", "target")):
                    m = re.search(r'(https?://[^\s"\'<>{}\)]+)', txt)
                    if m:
                        return m.group(1).strip(), None

            possible = soup.select_one("#origurl, .origurl, .destination, #destination")
            if possible and possible.get_text(strip=True):
                m = re.search(r'(https?://[^\s"\'<>{}\)]+)', possible.get_text())
                if m:
                    return m.group(1).strip(), None

        except Exception:
            pass

    m = re.search(r'"destination"\s*:\s*"([^"]+)"', html)
    if not m:
        m = re.search(r'"destinationUrl"\s*:\s*"([^"]+)"', html, flags=re.IGNORECASE)
    if not m:
        m = re.search(r'destination_url["\']?\s*[:=]\s*["\'](https?://[^"\']+)["\']', html, flags=re.IGNORECASE)
    if m:
        return m.group(1).strip(), None

    lower = html.lower()
    for keyword in ("destination", "redirect", "target", "url"):
        for mm in re.finditer(keyword, lower):
            start = max(0, mm.start() - 300)
            end = min(len(html), mm.end() + 300)
            window = html[start:end]
            found = re.search(r'(https?://[^\s"\'<>{}\)]+)', window)
            if found:
                return found.group(1).strip(), None

    try:
        r2 = requests.get(link, headers=headers, allow_redirects=True, timeout=10)
        final = getattr(r2, "url", None)
        if final and final != link:
            return final, None
    except Exception:
        pass

    return None, "❌ shorter.me: could not extract original URL."

def bypass_tinycc(link: str):
    """
    Best-effort tiny.cc unshortener.
    Tries both https and http, with and without trailing '=' (preview page).
    Returns (final_url, None) or (None, error_msg).
    """
    if not link:
        return None, "❌ Empty tiny.cc link."

    from urllib.parse import urlparse, urlunparse

    def build_variants(raw):
        if not raw.startswith("http"):
            raw = "https://" + raw
        p = urlparse(raw)
        if p.netloc.lower() != "tiny.cc":

            return [raw]

        path = p.path.rstrip("/")
        https_base = urlunparse(("https", "tiny.cc", path, "", "", ""))
        http_base  = urlunparse(("http",  "tiny.cc", path, "", "", ""))

        variants = [
            https_base,           
            http_base,            
            https_base + "=",     
            http_base + "=",      
        ]

        variants += [v + "/" for v in variants if not v.endswith("/")]

        seen, ordered = set(), []
        for v in variants:
            if v not in seen:
                seen.add(v)
                ordered.append(v)
        return ordered

    candidates = build_variants(link)

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Referer": "https://tiny.cc/"
    }

    def parse_original_from_html(html_text: str):
        if not html_text:
            return None

        m = re.search(r'Original\s+URL[\s:\-]*[^\n\r\t]*?(https?://[^\s"\'<>{}\)]+)', html_text, flags=re.I)
        if m:
            return m.group(1).strip()

        if BS4_AVAILABLE:
            try:
                soup = BeautifulSoup(html_text, "html.parser")

                for node in soup.find_all(text=lambda t: t and "Original URL" in t):
                    sib = node.parent.find_next_sibling()
                    if sib:
                        txt = sib.get_text(" ", strip=True)
                        m2 = re.search(r'(https?://[^\s"\'<>{}\)]+)', txt)
                        if m2:
                            return m2.group(1).strip()

                for sel in ("#recent", ".recent-item", ".recent-action-panel", ".origurl", ".long-url", "#origurl"):
                    el = soup.select_one(sel)
                    if el:
                        txt = el.get_text(" ", strip=True)
                        m3 = re.search(r'(https?://[^\s"\'<>{}\)]+)', txt)
                        if m3 and "tiny.cc" not in m3.group(1).lower():
                            return m3.group(1).strip()
            except Exception:
                pass

        for m4 in re.findall(r'(https?://[^\s"\'<>{}\)]+)', html_text):
            if "tiny.cc" not in m4.lower():
                return m4.strip()
        return None

    for url in candidates:

        try:
            r = requests.head(url, headers=headers, allow_redirects=False, timeout=8)
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location")
                if loc and "tiny.cc" not in loc.lower():
                    return loc.strip(), None
        except Exception:
            pass

        try:
            r = requests.get(url, headers=headers, allow_redirects=False, timeout=10)
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location")
                if loc and "tiny.cc" not in loc.lower():
                    return loc.strip(), None
        except Exception as e:

            continue

        try:
            r2 = requests.get(url, headers=headers, allow_redirects=True, timeout=12)
            final = getattr(r2, "url", None)
            if final and "tiny.cc" not in final.lower():
                return final, None
        except Exception:
            pass

        try:
            html = r.text if 'r' in locals() and r is not None and hasattr(r, "text") else ""
            if not html:

                resp = requests.get(url, headers=headers, allow_redirects=False, timeout=10)
                html = resp.text or ""
            found = parse_original_from_html(html)
            if found:
                return found, None
        except Exception:
            pass

        html_lower = (html or "").lower()
        if any(s in html_lower for s in ("cloudflare", "please enable javascript", "attention required", "cf-chl")):
            if PLAYWRIGHT_AVAILABLE:
                try:
                    from playwright.sync_api import sync_playwright
                    with sync_playwright() as p:
                        browser = p.chromium.launch(headless=True)
                        context = browser.new_context(user_agent=USER_AGENT)
                        page = context.new_page()
                        page.goto(url, wait_until="domcontentloaded", timeout=45000)
                        page.wait_for_timeout(2500)
                        final_url = page.url
                        content = page.content()
                        browser.close()
                        if final_url and "tiny.cc" not in final_url.lower():
                            return final_url, None

                        cand = parse_original_from_html(content or "")
                        if cand:
                            return cand, None
                except Exception:
                    pass

    return None, "❌ tiny.cc: could not extract original URL (tried http/https and preview)."

def bypass_tinylinkonl(link: str):
    """
    Unshorten tinylink.onl short links by extracting meta refresh or JS longUrl var.
    Returns (final_url, None) or (None, error_msg).
    """
    if not link:
        return None, "❌ Empty tinylink.onl link."
    if not link.startswith("http"):
        link = "https://" + link

    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}

    try:
        h = requests.head(link, headers=headers, allow_redirects=False, timeout=8)
        if h is not None and h.status_code in (301,302,303,307,308):
            loc = h.headers.get("Location")
            if loc and "tinylink.onl" not in loc.lower():
                return loc, None
    except Exception:
        pass

    try:
        r = requests.get(link, headers=headers, allow_redirects=False, timeout=12)
    except Exception as e:
        return None, f"❌ tinylink.onl request error: {e}"

    if r.status_code in (301,302,303,307,308):
        loc = r.headers.get("Location")
        if loc and "tinylink.onl" not in loc.lower():
            return loc, None

    html = r.text or ""

    try:
        m_meta = re.search(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*content=["\']?([^"\'>]+)["\']?', html, flags=re.I)
        if m_meta:
            content = m_meta.group(1)

            m_url = re.search(r'url\s*=\s*(.+)', content, flags=re.I)
            if not m_url:

                m_url = re.search(r';\s*(https?://[^\s"\']+)', content, flags=re.I)
            if m_url:
                candidate = m_url.group(1).strip().strip('\'"')

                if candidate and "tinylink.onl" not in candidate.lower():
                    return candidate, None
    except Exception:
        pass

    try:

        m_js = re.search(r'var\s+longUrl\s*=\s*["\']([^"\']+)["\']', html, flags=re.I)
        if m_js:
            raw = m_js.group(1)

            candidate = raw.replace('\\/', '/').strip()
            if candidate and candidate.startswith("http") and "tinylink.onl" not in candidate.lower():
                return candidate, None
    except Exception:
        pass

    try:
        for u in re.findall(r'(https?://[^\s"\'<>]+)', html):
            if "tinylink.onl" not in u.lower():
                return u, None
    except Exception:
        pass

    if PLAYWRIGHT_AVAILABLE:
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(user_agent=USER_AGENT)
                page = context.new_page()
                page.goto(link, wait_until="networkidle", timeout=30000)

                page.wait_for_timeout(1200)
                content = page.content() or ""
                browser.close()

                m_js2 = re.search(r'var\s+longUrl\s*=\s*["\']([^"\']+)["\']', content, flags=re.I)
                if m_js2:
                    candidate = m_js2.group(1).replace('\\/', '/').strip()
                    if candidate and "tinylink.onl" not in candidate.lower():
                        return candidate, None

                m_meta2 = re.search(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*content=["\']?([^"\'>]+)["\']?', content, flags=re.I)
                if m_meta2:
                    c = m_meta2.group(1)
                    m_url2 = re.search(r'url\s*=\s*(.+)', c, flags=re.I) or re.search(r';\s*(https?://[^\s"\']+)', c, flags=re.I)
                    if m_url2:
                        candidate = m_url2.group(1).strip().strip('\'"')
                        if candidate and "tinylink.onl" not in candidate.lower():
                            return candidate, None
        except Exception as e:

            return None, f"❌ tinylink.onl Playwright error: {e}"

    return None, "❌ tinylink.onl: could not extract original URL."

def bypass_tinyurl(link: str):
    """
    Unshorten tinyurl.com links.
    Strategy:
      1) HEAD for Location
      2) GET without redirects and check:
         - preview page (alias + '+') which often shows original URL
         - inline JSON like {"data":[{"url":"..."}]}
         - canonical / og / meta refresh
      3) Follow redirects (allow_redirects=True) as last resort
    Returns (final_url, None) or (None, error_msg).
    """
    if not link:
        return None, "❌ Empty tinyurl link."
    if not link.startswith("http"):
        link = "https://" + link

    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}

    try:
        try:
            h = requests.head(link, headers=headers, allow_redirects=False, timeout=8)
        except Exception:
            h = None
        if h is not None and h.status_code in (301,302,303,307,308):
            loc = h.headers.get("Location")
            if loc and "tinyurl.com" not in loc.lower():
                return loc, None
    except Exception:
        pass

    def parse_original_from_html(html_text: str):
        if not html_text:
            return None

        try:
            m = re.search(r'"data"\s*:\s*\[\s*\{\s*"url"\s*:\s*"([^"]+)"', html_text, flags=re.I)
            if m:
                cand = m.group(1).replace('\\/', '/').strip()
                if cand and not cand.lower().startswith("https://tinyurl.com"):
                    return cand
        except Exception:
            pass

        try:
            if BS4_AVAILABLE:
                soup = BeautifulSoup(html_text, "html.parser")

                link_tag = soup.find("link", rel="canonical")
                if link_tag and link_tag.get("href"):
                    href = link_tag["href"].strip()
                    if href and "tinyurl.com" not in href.lower():
                        return href
                og = soup.find("meta", property="og:url")
                if og and og.get("content"):
                    href = og["content"].strip()
                    if href and "tinyurl.com" not in href.lower():
                        return href

                meta = soup.find("meta", attrs={"http-equiv": "refresh"})
                if meta and meta.get("content"):
                    c = meta["content"]
                    m2 = re.search(r'url\s*=\s*(.+)', c, flags=re.I) or re.search(r';\s*(https?://[^\s"\']+)', c, flags=re.I)
                    if m2:
                        candidate = m2.group(1).strip().strip('\'"')
                        if candidate and "tinyurl.com" not in candidate.lower():
                            return candidate

                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.startswith("http") and "tinyurl.com" not in href.lower():
                        return href
        except Exception:
            pass

        try:
            for u in re.findall(r'(https?://[^\s"\'<>]+)', html_text):
                if "tinyurl.com" not in u.lower():
                    return u
        except Exception:
            pass

        return None

    try:
        r = requests.get(link, headers=headers, allow_redirects=False, timeout=12)
    except Exception as e:
        return None, f"❌ tinyurl request error: {e}"

    if r.status_code in (301,302,303,307,308):
        loc = r.headers.get("Location")
        if loc and "tinyurl.com" not in loc.lower():
            return loc, None

    html = r.text or ""

    try:

        parsed = urlparse(link)
        path = parsed.path or ""
        if path:

            alias = path.strip("/")
            preview_url = f"{parsed.scheme}://{parsed.netloc}/{alias}+"
            try:
                pr = requests.get(preview_url, headers=headers, allow_redirects=False, timeout=10)

                preview_html = pr.text or ""
                found = parse_original_from_html(preview_html)
                if found:
                    return found, None
            except Exception:
                pass
    except Exception:
        pass

    found = parse_original_from_html(html)
    if found:
        return found, None

    try:
        r2 = requests.get(link, headers=headers, allow_redirects=True, timeout=12)
        final = getattr(r2, "url", None)
        if final and "tinyurl.com" not in final.lower():
            return final, None
    except Exception:
        pass

    return None, "❌ tinyurl: could not extract original URL."

def bypass_vgd(link: str):
    """
    Unshorten v.gd links (v.gd/xYZ).
    Returns (final_url, None) or (None, error_msg).
    """
    if not link:
        return None, "❌ Empty v.gd link."
    if not link.startswith("http"):
        link = "https://" + link

    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}

    try:
        h = requests.head(link, headers=headers, allow_redirects=False, timeout=8)
        if h is not None and h.status_code in (301,302,303,307,308):
            loc = h.headers.get("Location")
            if loc and "v.gd" not in loc.lower():
                return loc, None
    except Exception:
        pass

    try:
        r = requests.get(link, headers=headers, allow_redirects=False, timeout=12)
    except Exception as e:
        return None, f"❌ v.gd request error: {e}"

    if r.status_code in (301,302,303,307,308):
        loc = r.headers.get("Location")
        if loc and "v.gd" not in loc.lower():
            return loc, None

    html = r.text or ""

    try:
        m_meta = re.search(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*content=["\']?([^"\'>]+)["\']?', html, flags=re.I)
        if m_meta:
            content = m_meta.group(1)
            m_url = re.search(r'url\s*=\s*(.+)', content, flags=re.I) or re.search(r';\s*(https?://[^\s"\']+)', content, flags=re.I)
            if m_url:
                cand = m_url.group(1).strip().strip('\'"')
                if cand and "v.gd" not in cand.lower():
                    return cand, None
    except Exception:
        pass

    try:
        m_js = re.search(r'var\s+longUrl\s*=\s*["\']([^"\']+)["\']', html, flags=re.I)
        if m_js:
            candidate = m_js.group(1).replace('\\/', '/').strip()
            if candidate and "v.gd" not in candidate.lower():
                return candidate, None
    except Exception:
        pass

    try:
        if BS4_AVAILABLE:
            soup = BeautifulSoup(html, "html.parser")

            el = soup.select_one("#origurl")
            if el:
                txt = el.get_text(" ", strip=True)
                m = re.search(r'(https?://[^\s"\'<>{}\)]+)', txt)
                if m:
                    cand = m.group(1).strip()
                    if "v.gd" not in cand.lower():
                        return cand, None

            for node in soup.find_all(string=re.compile(r'Your shortened URL goes to', flags=re.I)):
                parent = node.parent
                if parent:
                    a = parent.find_next("a", href=True)
                    if a and isinstance(a.get("href"), str):
                        href = a["href"].strip()
                        if href and "v.gd" not in href.lower():
                            return href, None

                    m2 = re.search(r'(https?://[^\s"\'<>{}\)]+)', parent.get_text(" ", strip=True))
                    if m2:
                        cand = m2.group(1).strip()
                        if "v.gd" not in cand.lower():
                            return cand, None

            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if href.startswith("http") and "v.gd" not in href.lower():
                    return href, None
    except Exception:
        pass

    try:
        for u in re.findall(r'(https?://[^\s"\'<>]+)', html):
            if "v.gd" not in u.lower():
                return u, None
    except Exception:
        pass

    if PLAYWRIGHT_AVAILABLE:
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(user_agent=USER_AGENT)
                page = context.new_page()
                page.goto(link, wait_until="networkidle", timeout=30000)
                page.wait_for_timeout(800)
                content = page.content() or ""
                browser.close()

                m = re.search(r'(https?://[^\s"\'<>]+)', content)
                if m and "v.gd" not in m.group(1).lower():
                    return m.group(1).strip(), None
        except Exception as e:
            return None, f"❌ v.gd Playwright error: {e}"

    try:
        final_resp = requests.get(link, headers=headers, allow_redirects=True, timeout=12)
        final = getattr(final_resp, "url", None)
        if final and "v.gd" not in final.lower():
            return final, None
    except Exception:
        pass

    return None, "❌ v.gd: could not extract original URL."

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        link = request.form.get("link", "").strip()
        if not link:
            return render_template_string(HTML_TEMPLATE, error="❌ Please enter a link.")
        result, error = auto_detect_bypass(link)
        if error:
            return render_template_string(HTML_TEMPLATE, error=error)
        return render_template_string(HTML_TEMPLATE, result=result)
    return render_template_string(HTML_TEMPLATE)

def auto_detect_bypass(link: str):
    if not link:
        return None, "❌ Empty link."
    link_lower = normalize_link_for_detection(link)

    if "ytsubme.com" in link_lower or "/s2u/" in link_lower:
        code = extract_code_from_url(link)
        return bypass_ytsubme(code)

    if "unlocknow.net" in link_lower:
        return bypass_unlocknow(link)

    if "subfinal.com" in link_lower:
        return bypass_subfinal(link)

    if "sub2unlock.net" in link_lower or "sub2unlock" in link_lower:
        parsed = urlparse(link)
        code = parsed.path.strip("/").split("/")[-1] if parsed.path else link
        return bypass_sub2unlock(code)

    if "sub4unlock.io" in link_lower or "sub4unlock" in link_lower:
        return bypass_sub4unlock(link)

    if "rekonise.com" in link_lower or "api.rekonise.com" in link_lower:
        parsed = urlparse(link)
        code = parsed.path.strip("/").split("/")[-1] if parsed.path else link
        return bypass_rekonise(code)

    if "paste-drop.com" in link_lower or "/paste/" in link_lower:
        return bypass_paste_drop(link)

    if "pastebin.com" in link_lower:
        return bypass_pastebin(link)

    if "justpaste.it" in link_lower:
        return bypass_justpaste_it(link)

    if "mboost.me" in link_lower or "api.mboost.me" in link_lower:
        return bypass_mboost(link)

    if any(domain in link_lower for domain in ("boost.ink", "bst.gg", "booo.st", "bst.wtf")):
        return bypass_boost(link)

    if any(domain in link_lower for domain in ("bit.ly", "j.mp", "bitly.com")):
        return bypass_bitly(link)

    if "adfoc.us" in link_lower or "adfoc" in link_lower:
        return bypass_adfoc(link)

    if "bstshrt.com" in link_lower:
        return bypass_bstshrt(link)

    if "link-unlock.com" in link_lower or "api.link-unlock.com" in link_lower:
        return bypass_link_unlock(link)

    if "is.gd" in link_lower:
        return bypass_isgd(link)

    if "rebrand.ly" in link_lower or "rebrandly.com" in link_lower:
        return bypass_rebrandly(link)

    if "shorter.me" in link_lower:
        return bypass_shorterme(link)

    if "tiny.cc" in link_lower:
        return bypass_tinycc(link)

    if "tinylink.onl" in link_lower:
        return bypass_tinylinkonl(link)

    if "tinyurl.com" in link_lower:
        return bypass_tinyurl(link)

    if "v.gd" in link_lower or "is.gd" in link_lower:
        return bypass_vgd(link)

    return None, "❌ Unsupported platform. Add support for this service."

@app.route("/", methods=["GET", "POST"])
def home():
    result_url = None
    error_msg = None
    if request.method == "POST":
        link = request.form.get("link", "").strip()
        if link:
            result_url, error_msg = auto_detect_bypass(link)
        else:
            error_msg = "❌ Please provide a valid link."
    return render_template_string(HTML_TEMPLATE, result=result_url, error=error_msg)

register_bypass_routes(app, globals())

@app.route("/_routes")
def list_routes():
    return {
        "routes": [r.rule for r in app.url_map.iter_rules()]
    }, 200

if __name__ == "__main__":
    import os
    PORT = int(os.environ.get("PORT", 5004))
    app.run(host="0.0.0.0", port=PORT, debug=True)
