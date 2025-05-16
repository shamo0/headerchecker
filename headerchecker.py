import requests
import re

# Core headers with adjusted weights based on importance
SECURITY_HEADERS = {
    "Content-Security-Policy": {"weight": 25, "function": "check_csp"},
    "Strict-Transport-Security": {"weight": 20, "function": "check_hsts"},
    "Permissions-Policy": {"weight": 15, "function": "check_permissions"},
    "Referrer-Policy": {"weight": 10, "function": "check_referrer"},
    "X-Content-Type-Options": {"weight": 10, "function": "check_xcto"},
    "X-Frame-Options": {"weight": 10, "function": "check_xfo"},
    "X-XSS-Protection": {"weight": 5, "function": "check_xss"},
}

# Bonus headers
BONUS_HEADERS = {
    "Cross-Origin-Embedder-Policy": 2,
    "Cross-Origin-Opener-Policy": 2,
    "Cross-Origin-Resource-Policy": 2,
    "Expect-CT": 2,
    "NEL": 2,
    "Report-To": 2
}

GRADE_THRESHOLDS = [
    (85, "A+"), (75, "A"), (65, "B"), (50, "C"),
    (35, "D"), (20, "E"), (0, "F")
]

# --- Validators ---

def check_csp(value, headers):
    if not value:
        value = headers.get("content-security-policy-report-only", "")
        if not value:
            return 0, "Missing Content-Security-Policy"
    if "unsafe-inline" in value or "unsafe-eval" in value:
        if "nonce-" in value or re.search(r"'sha\d{3}-", value):
            return 25, None
        return 10, "CSP uses unsafe-inline or unsafe-eval without nonce/hash"
    return 25, None

def check_hsts(value):
    if not value:
        return 0, "Missing Strict-Transport-Security"
    if "max-age=0" in value:
        return 0, "HSTS disables HTTPS"
    return 20, None

def check_permissions(value):
    return (15, None) if value else (0, "Missing Permissions-Policy")

def check_referrer(value):
    if not value:
        return 0, "Missing Referrer-Policy"
    if "unsafe-url" in value:
        return 5, "Referrer Policy is unsafe-url"
    return 10, None

def check_xcto(value):
    return (10, None) if value.lower() == "nosniff" else (0, "Missing or misconfigured X-Content-Type-Options")

def check_xfo(value, headers):
    if value.upper() in ["DENY", "SAMEORIGIN"]:
        return 10, None
    csp = headers.get("content-security-policy", "")
    if "frame-ancestors" in csp:
        return 10, None
    return 0, "Missing or weak X-Frame-Options and no frame-ancestors in CSP"

def check_xss(value):
    if not value:
        return 0, "Missing X-XSS-Protection"
    if value.startswith("1"):
        return 5, None
    return 0, "X-XSS-Protection disabled"

def check_server_leak(value):
    if not value or "cloudflare" in value.lower() or value.lower() in ["", "magic"]:
        return 2, None
    return 0, f"Server header reveals backend: {value}"

def check_cookie_security(headers):
    cookies = headers.get("set-cookie", "")
    missing_flags = []
    for cookie in cookies.split(","):
        lower = cookie.lower()
        if "secure" not in lower:
            missing_flags.append("Secure")
        if "httponly" not in lower:
            missing_flags.append("HttpOnly")
        if "samesite" not in lower:
            missing_flags.append("SameSite")
    if missing_flags:
        return 0, f"Set-Cookie missing flags: {', '.join(sorted(set(missing_flags)))}"
    return 5, None

VALIDATORS = {
    "check_csp": check_csp,
    "check_hsts": check_hsts,
    "check_permissions": check_permissions,
    "check_referrer": check_referrer,
    "check_xcto": check_xcto,
    "check_xfo": check_xfo,
    "check_xss": check_xss
}

def fetch_headers(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        return response.headers
    except Exception as e:
        print(f"Failed to fetch headers: {e}")
        return {}

def calculate_grade(score):
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"

def evaluate(headers):
    headers = {k.lower(): v for k, v in headers.items()}
    total_score = 0
    deductions = []
    bonus = 0

    for header, meta in SECURITY_HEADERS.items():
        value = headers.get(header.lower(), "")
        validate = VALIDATORS[meta["function"]]
        if meta["function"] == "check_xfo":
            score, reason = validate(value, headers)
        elif meta["function"] == "check_csp":
            score, reason = validate(value, headers)
        else:
            score, reason = validate(value)
        total_score += score
        if reason:
            deductions.append(f"{header}: {reason}")

    # Bonus headers
    for header, points in BONUS_HEADERS.items():
        if header.lower() in headers:
            bonus += points

    server_score, server_issue = check_server_leak(headers.get("server", ""))
    total_score += server_score
    if server_issue:
        deductions.append(f"Server: {server_issue}")

    cookie_score, cookie_issue = check_cookie_security(headers)
    total_score += cookie_score
    if cookie_issue:
        deductions.append(f"Set-Cookie: {cookie_issue}")

    full_score = total_score + bonus
    grade = calculate_grade(full_score)

    return {
        "score": full_score,
        "grade": grade,
        "deductions": deductions,
        "bonus": bonus
    }

def run_scanner(url):
    if not url.startswith("http"):
        url = "https://" + url

    print(f"\nScanning: {url}")
    headers = fetch_headers(url)
    result = evaluate(headers)

    print("\n--- Security Headers Report ---")
    print(f"Total Score: {result['score']} / 100+")
    print(f"Grade: {result['grade']}")
    print(f"Bonus from additional headers: {result['bonus']}")

    if result["deductions"]:
        print("\nIssues Detected:")
        for d in result["deductions"]:
            print(f" - {d}")
    else:
        print("\nAll core headers are present and secure!")

if __name__ == "__main__":
    target_url = input("Enter a domain or full URL to scan: ")
    run_scanner(target_url)

