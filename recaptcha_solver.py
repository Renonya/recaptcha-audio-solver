#!/usr/bin/env python3
"""Local reCAPTCHA solver. No captcha farms.

Uses a patched real Chrome (patchright) to click the v2 checkbox.
If Google serves an image challenge, switches to audio, transcribes
with Google's speech endpoint, and submits the answer.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

from pyvda import AppView, VirtualDesktop, get_virtual_desktops

import imageio_ffmpeg
import speech_recognition as sr
from patchright.sync_api import Page, Playwright, sync_playwright

HERE = Path(__file__).resolve().parent
FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()

DEMO_URL = "https://www.google.com/recaptcha/api2/demo"
DEMO_SITEKEY = "6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-"

ANCHOR_SEL = 'iframe[src*="recaptcha"][src*="anchor"]'
BFRAME_SEL = 'iframe[src*="recaptcha"][src*="bframe"]'

WORD_TO_DIGIT = {
    "zero": "0",
    "one": "1",
    "two": "2",
    "three": "3",
    "four": "4",
    "five": "5",
    "six": "6",
    "seven": "7",
    "eight": "8",
    "nine": "9",
    "oh": "0",
    "nought": "0",
    "ゼロ": "0",
    "零": "0",
    "いち": "1",
    "一": "1",
    "に": "2",
    "二": "2",
    "さん": "3",
    "三": "3",
    "よん": "4",
    "し": "4",
    "四": "4",
    "ご": "5",
    "五": "5",
    "ろく": "6",
    "六": "6",
    "なな": "7",
    "しち": "7",
    "七": "7",
    "はち": "8",
    "八": "8",
    "きゅう": "9",
    "く": "9",
    "九": "9",
}

STT_LANG = {
    "en": "en-US",
    "en-US": "en-US",
    "en-GB": "en-GB",
    "ja": "ja-JP",
    "ja-JP": "ja-JP",
}


class RecaptchaError(RuntimeError):
    pass


def log(msg: str) -> None:
    print(msg, flush=True)


def jitter(a: float, b: float) -> None:
    time.sleep(random.uniform(a, b))


def bezier(p0: float, p1: float, p2: float, p3: float, t: float) -> float:
    u = 1.0 - t
    return u**3 * p0 + 3 * u**2 * t * p1 + 3 * u * t**2 * p2 + t**3 * p3


def human_move_click(page: Page, x: float, y: float) -> None:
    sx, sy = getattr(page, "_mouse_pos", (random.randint(40, 240), random.randint(40, 180)))
    dx, dy = x - sx, y - sy
    c1x = sx + dx * random.uniform(0.15, 0.4) + random.uniform(-80, 80)
    c1y = sy + dy * random.uniform(0.05, 0.35) + random.uniform(-80, 80)
    c2x = sx + dx * random.uniform(0.55, 0.85) + random.uniform(-80, 80)
    c2y = sy + dy * random.uniform(0.6, 0.95) + random.uniform(-80, 80)
    steps = random.randint(22, 38)
    for i in range(steps + 1):
        t = i / steps
        # ease-in-out
        te = t * t * (3 - 2 * t)
        px = bezier(sx, c1x, c2x, x, te) + random.uniform(-0.6, 0.6)
        py = bezier(sy, c1y, c2y, y, te) + random.uniform(-0.6, 0.6)
        page.mouse.move(px, py)
        page.wait_for_timeout(random.randint(4, 16))
    page.wait_for_timeout(random.randint(60, 220))
    page.mouse.down()
    page.wait_for_timeout(random.randint(35, 110))
    page.mouse.up()
    page._mouse_pos = (x, y)


def extract_token_js() -> str:
    return """() => {
      const areas = document.querySelectorAll(
        '#g-recaptcha-response, textarea[name="g-recaptcha-response"]'
      );
      for (const el of areas) {
        if (el.value && el.value.length > 40) return el.value;
      }
      try {
        if (window.grecaptcha && grecaptcha.getResponse) {
          const t = grecaptcha.getResponse();
          if (t) return t;
        }
      } catch (e) {}
      try {
        if (window.grecaptcha && grecaptcha.enterprise && grecaptcha.enterprise.getResponse) {
          const t = grecaptcha.enterprise.getResponse();
          if (t) return t;
        }
      } catch (e) {}
      return null;
    }"""


def normalize_answer(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    parts = [p for p in text.split() if p]
    mapped = [WORD_TO_DIGIT.get(p, p) for p in parts]
    joined = "".join(mapped)
    if re.fullmatch(r"\d+", joined) and len(joined) >= 4:
        return joined
    return " ".join(parts)


def transcribe_wav(wav_path: Path, lang: str = "en-US") -> str:
    recognizer = sr.Recognizer()
    recognizer.energy_threshold = 50
    with sr.AudioFile(str(wav_path)) as source:
        audio = recognizer.record(source)
    last_err: Optional[Exception] = None
    for candidate in (lang, "en-US", "ja-JP"):
        try:
            return recognizer.recognize_google(audio, language=candidate)
        except sr.UnknownValueError as exc:
            last_err = exc
            continue
        except sr.RequestError as exc:
            raise RecaptchaError(f"speech recognition request failed: {exc}") from exc
    raise RecaptchaError("speech recognition heard nothing") from last_err


def _hwnds_with_title(part: str) -> list[int]:
    user32 = ctypes.windll.user32
    found: list[int] = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def _cb(hwnd, _lparam):
        n = user32.GetWindowTextLengthW(hwnd)
        if n:
            buf = ctypes.create_unicode_buffer(n + 1)
            user32.GetWindowTextW(hwnd, buf, n + 1)
            if part in buf.value:
                found.append(int(hwnd))
        return True

    user32.EnumWindows(_cb, 0)
    return found


class HiddenDesktop:
    """Park headed Chrome on a Windows virtual desktop (pyvda)."""

    NAME = "rc-solver"

    def __init__(self) -> None:
        self.vd: Optional[VirtualDesktop] = None
        self.created = False

    def park(self, page: Page) -> None:
        marker = f"rc-solver-{random.randint(100000, 999999)}"
        try:
            page.evaluate("(t) => { document.title = t; }", marker)
        except Exception:
            pass
        hwnd = None
        for _ in range(25):
            hits = _hwnds_with_title(marker)
            if hits:
                hwnd = hits[0]
                break
            page.wait_for_timeout(80)
        if hwnd is None:
            log("[solver] virtual desktop: chrome hwnd not found")
            return
        existing = next((d for d in get_virtual_desktops() if d.name == self.NAME), None)
        if existing is None:
            self.vd = VirtualDesktop.create()
            self.created = True
            try:
                self.vd.rename(self.NAME)
            except Exception:
                pass
        else:
            self.vd = existing
        AppView(hwnd).move(self.vd)
        ctypes.windll.user32.SetWindowPos(hwnd, 0, 0, 0, 1920, 1080, 0x0040)
        log(f"[solver] parked chrome hwnd={hwnd} on virtual desktop")

    def close(self) -> None:
        if self.created and self.vd is not None:
            try:
                self.vd.remove()
            except Exception:
                pass


def mp3_to_wav(mp3_path: Path, wav_path: Path) -> None:
    cmd = [
        FFMPEG,
        "-y",
        "-i",
        str(mp3_path),
        "-ac",
        "1",
        "-ar",
        "16000",
        "-c:a",
        "pcm_s16le",
        str(wav_path),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0 or not wav_path.is_file():
        raise RecaptchaError(f"ffmpeg failed: {proc.stderr[-400:]}")


class RecaptchaSolver:
    def __init__(
        self,
        headless: bool = True,
        timeout: float = 120.0,
        audio_rounds: int = 5,
    ) -> None:
        self.headless = headless
        self.timeout = timeout
        self.audio_rounds = audio_rounds
        self._tmp: Optional[Path] = None

    def _launch(self, pw: Playwright, user_data: Path):
        args = [
            "--disable-blink-features=AutomationControlled",
            "--lang=en-US",
            "--no-first-run",
            "--no-default-browser-check",
            "--window-size=1920,1080",
        ]
        kwargs: dict = {
            "channel": "chrome",
            "headless": False,
            "locale": "en-US",
            "timezone_id": "America/New_York",
            "extra_http_headers": {"Accept-Language": "en-US,en;q=0.9"},
            "ignore_default_args": ["--enable-automation"],
            "args": args,
        }
        if self.headless:
            kwargs["viewport"] = {"width": 1920, "height": 1080}
            args.append("--window-position=-32000,-32000")
        else:
            kwargs["no_viewport"] = True
        return pw.chromium.launch_persistent_context(str(user_data), **kwargs)

    def _with_browser(self, fn):
        user_data = Path(tempfile.mkdtemp(prefix="rc-chrome-"))
        hidden = HiddenDesktop() if self.headless else None
        try:
            with sync_playwright() as pw:
                context = self._launch(pw, user_data)
                try:
                    page = context.pages[0] if context.pages else context.new_page()
                    if hidden:
                        hidden.park(page)
                    return fn(page)
                finally:
                    context.close()
        finally:
            if hidden:
                hidden.close()
            shutil.rmtree(user_data, ignore_errors=True)

    def solve(self, url: str, sitekey: Optional[str] = None) -> str:
        def _run(page: Page) -> str:
            try:
                return self._solve_on_page(page, url, sitekey)
            except Exception:
                self._dump(page)
                raise

        return self._with_browser(_run)

    def solve_and_submit_demo(self) -> tuple[bool, str]:
        def _run(page: Page) -> tuple[bool, str]:
            try:
                token = self._solve_on_page(page, DEMO_URL, DEMO_SITEKEY)
                page.locator("#recaptcha-demo-submit").click()
                page.wait_for_timeout(1500)
                html = page.content()
                ok = "Verification Success" in html or "recaptcha-success" in html
                if not ok:
                    self._dump(page)
                return ok, token
            except Exception:
                self._dump(page)
                raise

        return self._with_browser(_run)

    def _dump(self, page: Page) -> None:
        try:
            page.screenshot(path=str(HERE / "last_fail.png"), full_page=True)
        except Exception:
            pass
        try:
            (HERE / "last_fail.html").write_text(page.content(), encoding="utf-8")
        except Exception:
            pass

    def _force_english_recaptcha(self, page: Page) -> None:
        def _rewrite(route):
            req_url = route.request.url
            if "recaptcha" in req_url and "hl=" in req_url:
                req_url = re.sub(r"hl=[^&]*", "hl=en", req_url)
            elif "recaptcha/api.js" in req_url and "hl=" not in req_url:
                req_url = req_url + ("&" if "?" in req_url else "?") + "hl=en"
            route.continue_(url=req_url)

        page.route("**/*recaptcha*", _rewrite)

    def _iframe_lang(self, page: Page) -> str:
        try:
            src = page.locator(ANCHOR_SEL).first.get_attribute("src") or ""
        except Exception:
            src = ""
        m = re.search(r"[?&]hl=([^&]+)", src)
        hl = m.group(1) if m else "en"
        return STT_LANG.get(hl, STT_LANG.get(hl.split("-")[0], "en-US"))

    def _solve_on_page(self, page: Page, url: str, sitekey: Optional[str]) -> str:
        self._force_english_recaptcha(page)
        log(f"[solver] goto {url} hidden_desktop={self.headless}")
        page.goto(url, wait_until="domcontentloaded", timeout=int(self.timeout * 1000))
        try:
            page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        jitter(1.2, 2.4)

        token = page.evaluate(extract_token_js())
        if token:
            log("[solver] token already present")
            return token

        if page.locator(ANCHOR_SEL).count() == 0:
            if sitekey:
                log("[solver] iframe missing, injecting widget")
                self._inject_widget(page, sitekey)
            else:
                try:
                    page.wait_for_selector(ANCHOR_SEL, timeout=25000)
                except Exception:
                    raise RecaptchaError("no reCAPTCHA iframe on page")

        jitter(0.6, 1.4)
        self._click_checkbox(page)

        deadline = time.time() + self.timeout
        audio_tries = 0
        while time.time() < deadline:
            token = page.evaluate(extract_token_js())
            if token:
                log(f"[solver] got token len={len(token)}")
                return token
            if self._blocked(page):
                raise RecaptchaError("google served 'try again later' (bot wall)")
            if self._checkbox_checked(page):
                page.wait_for_timeout(800)
                token = page.evaluate(extract_token_js())
                if token:
                    return token
            if self._challenge_open(page):
                if audio_tries >= self.audio_rounds:
                    raise RecaptchaError("audio challenge retries exhausted")
                audio_tries += 1
                log(f"[solver] audio round {audio_tries}/{self.audio_rounds}")
                self._solve_audio_round(page)
            page.wait_for_timeout(400)
        raise RecaptchaError("timeout waiting for recaptcha token")

    def _inject_widget(self, page: Page, sitekey: str) -> None:
        page.evaluate(
            """(key) => {
              if (document.querySelector('.g-recaptcha')) return;
              const box = document.createElement('div');
              box.className = 'g-recaptcha';
              box.setAttribute('data-sitekey', key);
              document.body.prepend(box);
              const s = document.createElement('script');
              s.src = 'https://www.google.com/recaptcha/api.js';
              s.async = true;
              s.defer = true;
              document.head.appendChild(s);
            }""",
            sitekey,
        )
        page.wait_for_selector(ANCHOR_SEL, timeout=30000)

    def _click_box(self, page: Page, loc, label: str) -> None:
        loc.wait_for(state="visible", timeout=15000)
        box = loc.bounding_box()
        if not box or box["width"] < 2 or box["height"] < 2:
            log(f"[solver] {label}: no box, locator.click()")
            loc.click(timeout=5000)
            return
        x = box["x"] + box["width"] / 2 + random.uniform(-2.5, 2.5)
        y = box["y"] + box["height"] / 2 + random.uniform(-2.5, 2.5)
        log(f"[solver] clicking {label} at ({x:.0f},{y:.0f}) size={box['width']:.0f}x{box['height']:.0f}")
        human_move_click(page, x, y)

    def _click_checkbox(self, page: Page) -> None:
        loc = page.locator(ANCHOR_SEL).first
        loc.wait_for(state="visible", timeout=30000)
        box = loc.bounding_box()
        if not box:
            raise RecaptchaError("anchor iframe has no box")
        # checkbox sits on the left of the 302x78 anchor iframe
        x = box["x"] + min(28, box["width"] * 0.12) + random.uniform(-3, 3)
        y = box["y"] + box["height"] / 2 + random.uniform(-4, 4)
        log(f"[solver] clicking checkbox at ({x:.0f},{y:.0f})")
        human_move_click(page, x, y)

    def _checkbox_checked(self, page: Page) -> bool:
        try:
            frame = page.frame_locator(ANCHOR_SEL)
            return frame.locator("#recaptcha-anchor[aria-checked='true']").count() > 0
        except Exception:
            return False

    def _challenge_open(self, page: Page) -> bool:
        try:
            loc = page.locator(BFRAME_SEL)
            if loc.count() == 0:
                return False
            box = loc.first.bounding_box()
            if not box:
                return False
            return box["width"] > 50 and box["height"] > 50
        except Exception:
            return False

    def _blocked(self, page: Page) -> bool:
        try:
            frame = page.frame_locator(BFRAME_SEL)
            body = frame.locator("body").inner_text(timeout=500)
        except Exception:
            return False
        low = body.lower()
        return (
            "try again later" in low
            or "automated queries" in low
            or "your computer or network" in low
        )

    def _solve_audio_round(self, page: Page) -> None:
        b = page.frame_locator(BFRAME_SEL)
        audio_btn = b.locator("#recaptcha-audio-button, .rc-button-audio")
        audio_input = b.locator("#audio-response")

        audio_btn.wait_for(state="visible", timeout=15000)
        jitter(0.8, 1.6)

        if not audio_input.is_visible():
            log("[solver] switching to audio challenge")
            try:
                self._click_box(page, audio_btn, "audio-button")
            except Exception as exc:
                log(f"[solver] audio-button human click failed ({exc}), fallback click")
                audio_btn.click(force=True)
            try:
                audio_input.wait_for(state="visible", timeout=12000)
            except Exception:
                self._dump(page)
                if self._blocked(page):
                    raise RecaptchaError("google served 'try again later' after audio switch")
                raise RecaptchaError("audio UI did not appear after clicking headphones")

        if self._blocked(page):
            raise RecaptchaError("google served 'try again later' after audio switch")

        jitter(0.4, 0.9)
        src = self._audio_src(page)
        if not src:
            try:
                self._click_box(page, b.locator("#recaptcha-reload-button"), "reload")
                jitter(1.0, 2.0)
            except Exception:
                pass
            src = self._audio_src(page)
        if not src:
            self._dump(page)
            raise RecaptchaError("no audio source in challenge iframe")

        log(f"[solver] downloading audio {src[:80]}...")
        resp = page.request.get(src)
        if not resp.ok:
            raise RecaptchaError(f"audio download HTTP {resp.status}")
        data = resp.body()
        if len(data) < 200:
            raise RecaptchaError("audio payload too small")

        work = Path(tempfile.mkdtemp(prefix="rc-audio-"))
        try:
            mp3 = work / "challenge.mp3"
            wav = work / "challenge.wav"
            mp3.write_bytes(data)
            mp3_to_wav(mp3, wav)
            lang = self._iframe_lang(page)
            raw = transcribe_wav(wav, lang)
            answer = normalize_answer(raw)
            log(f"[solver] stt[{lang}]={raw!r} -> {answer!r}")
        finally:
            shutil.rmtree(work, ignore_errors=True)

        if not answer:
            raise RecaptchaError("empty transcription")

        inp = b.locator("#audio-response")
        inp.wait_for(state="visible", timeout=10000)
        inp.click()
        jitter(0.15, 0.4)
        inp.press_sequentially(answer, delay=random.randint(55, 130))
        jitter(0.25, 0.6)
        b.locator("#recaptcha-verify-button").click()
        jitter(1.5, 2.8)

    def _audio_src(self, page: Page) -> Optional[str]:
        b = page.frame_locator(BFRAME_SEL)
        selectors = (
            "#audio-source",
            "audio#audio-source",
            "audio source",
            "audio",
            ".rc-audiochallenge-tdownload-link",
            "a[href*='payload']",
        )
        for _ in range(12):
            for sel in selectors:
                try:
                    loc = b.locator(sel).first
                    if loc.count() == 0:
                        continue
                    src = loc.get_attribute("src") or loc.get_attribute("href")
                    if src:
                        if src.startswith("//"):
                            src = "https:" + src
                        elif src.startswith("/"):
                            src = "https://www.google.com" + src
                        return src
                except Exception:
                    continue
            page.wait_for_timeout(250)
        return None


def cmd_solve(args: argparse.Namespace) -> int:
    solver = RecaptchaSolver(headless=not args.headed, timeout=args.timeout)
    last: Optional[str] = None
    for i in range(1, args.retries + 1):
        log(f"[solve] attempt {i}/{args.retries}")
        try:
            token = solver.solve(args.url, args.sitekey)
            if args.out:
                Path(args.out).write_text(token, encoding="utf-8")
            print(token)
            return 0
        except Exception as exc:
            last = f"{type(exc).__name__}: {exc}"
            log(f"[solve] FAIL {last}")
            time.sleep(2)
    log(f"[solve] giving up: {last}")
    return 1


def cmd_verify(args: argparse.Namespace) -> int:
    solver = RecaptchaSolver(headless=not args.headed, timeout=args.timeout)
    last: Optional[str] = None
    for i in range(1, args.retries + 1):
        log(f"[verify] attempt {i}/{args.retries}")
        try:
            ok, token = solver.solve_and_submit_demo()
            log(f"[verify] token len={len(token)} prefix={token[:24]}...")
            if ok:
                log("[verify] OK — Google accepted the token")
                print(token)
                return 0
            last = "demo page did not show Verification Success"
            log(f"[verify] FAIL {last}")
        except Exception as exc:
            last = f"{type(exc).__name__}: {exc}"
            log(f"[verify] FAIL {last}")
        time.sleep(3)
    log(f"[verify] giving up: {last}")
    return 1


def cmd_detect(args: argparse.Namespace) -> int:
    import requests

    r = requests.get(
        args.url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36"
        },
        timeout=30,
    )
    r.raise_for_status()
    html = r.text
    m = re.search(r'data-sitekey=["\']([A-Za-z0-9_-]{20,})["\']', html)
    sitekey = m.group(1) if m else None
    kind = "v2"
    if re.search(r"grecaptcha\.execute\(|api\.js\?render=", html):
        kind = "v3"
    if re.search(r'data-size=["\']invisible["\']', html, re.I):
        kind = "v2_invisible"
    print(json.dumps({"url": r.url, "sitekey": sitekey, "type": kind}, indent=2))
    return 0 if sitekey else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="local reCAPTCHA solver (no captcha farm)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("solve", help="open url, solve, print token")
    s.add_argument("--url", required=True)
    s.add_argument("--sitekey")
    s.add_argument("--timeout", type=float, default=120.0)
    s.add_argument("--retries", type=int, default=3)
    s.add_argument("--headed", action="store_true", help="show the browser window")
    s.add_argument("--out")
    s.set_defaults(func=cmd_solve)

    v = sub.add_parser("verify", help="solve Google's official demo end-to-end")
    v.add_argument("--timeout", type=float, default=120.0)
    v.add_argument("--retries", type=int, default=5)
    v.add_argument("--headed", action="store_true", help="show the browser window")
    v.set_defaults(func=cmd_verify)

    d = sub.add_parser("detect", help="extract sitekey from a page")
    d.add_argument("url")
    d.set_defaults(func=cmd_detect)
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except RecaptchaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
